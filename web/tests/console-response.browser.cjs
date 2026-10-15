// Real hooks, React and CSS; all API answers are in-memory fakes and outside requests are blocked.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, openConsole, preview, settled, inBounds, assertClean } = require("./console-proof.cjs");

async function refreshHook(browser) {
  const app = bundle({ React: "react", client: "react-dom/client", data: "@/console/data.ts" });
  const context = await browser.newContext();
  await context.clock.install();
  await context.addInitScript(value => { window.__fixture = value; }, app.data);
  const calls = [], errors = [];
  let releaseFirst, releaseRefresh, delay = false;
  const html = `<html><body><div id="root"></div><script>${app.preamble}
    function Reads(){const read=data.useApi('snapshot'), manual=data.useApi('explicit',{every:0}), fast=data.useApi('fast',{every:3000}), saved=data.useSaved();
      return React.createElement('div',null,React.createElement('output',{id:'value'},String(read.data?.value??'')),React.createElement('output',{id:'loading'},String(read.loading)),
        React.createElement('button',{id:'save',onClick:saved},'save'),React.createElement('button',{id:'replace',onClick:()=>read.replace({value:'replacement'})},'replace'));}
    function App(){const [revision,setRevision]=React.useState(0), saved=React.useCallback(()=>setRevision(n=>n+1),[]), authLost=React.useCallback(()=>{},[]);
      return React.createElement(data.ChangesContext.Provider,{value:{revision,saved,authLost}},React.createElement(Reads));}
    client.createRoot(document.getElementById('root')).render(React.createElement(App));</script></body></html>`;
  await context.route("**/*", async route => {
    const req = route.request(), url = new URL(req.url());
    if (url.origin !== ORIGIN) { errors.push(url.origin); return route.abort(); }
    if (req.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
    const endpoint = url.pathname.split("/").pop(); calls.push(endpoint);
    let value = "new";
    if (endpoint === "snapshot" && calls.filter(p => p === endpoint).length === 1) {
      value = await new Promise(resolve => { releaseFirst = resolve; });
    } else if (endpoint === "snapshot" && delay) {
      delay = false; value = await new Promise(resolve => { releaseRefresh = resolve; });
    }
    return route.fulfill({ contentType: "application/json", body: JSON.stringify({ value }) });
  });
  const page = await context.newPage();
  try {
    await page.goto(ORIGIN);
    await page.locator("#save").click();
    await page.waitForFunction(() => document.querySelector("#value").textContent === "new");
    assert.equal(calls.filter(p => p === "snapshot").length, 2, "post-save read never shares pre-save response");
    releaseFirst("old");
    await page.waitForTimeout(80);
    assert.equal(await page.locator("#value").textContent(), "new");
    assert.equal(calls.filter(p => p === "explicit").length, 1, "save never repeats explicit provider lookup");
    const faster = calls.filter(p => p === "fast").length;
    await page.clock.fastForward(3001);
    await page.waitForTimeout(80);
    assert.ok(calls.filter(p => p === "fast").length > faster, "faster existing cadence preserved");
    delay = true;
    await page.evaluate(() => dispatchEvent(new Event("focus")));
    await page.waitForTimeout(80);
    assert.equal(await page.locator("#loading").textContent(), "false", "background refresh keeps loaded content");
    await page.locator("#replace").click();
    releaseRefresh("stale refresh");
    await page.waitForTimeout(80);
    assert.equal(await page.locator("#value").textContent(), "replacement", "replace fences an old in-flight read");
    const before = calls.length;
    await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" }); document.dispatchEvent(new Event("visibilitychange")); });
    await page.clock.fastForward(30001);
    await page.waitForTimeout(80);
    assert.equal(calls.length, before, "hidden tabs do not poll");
    await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" }); document.dispatchEvent(new Event("visibilitychange")); });
    await page.waitForTimeout(80);
    assert.ok(calls.length > before, "returning to the tab refreshes immediately");
    assert.equal(calls.filter(p => p === "explicit").length, 1, "focus and polling never repeat explicit lookup");
    assert.deepEqual(errors, []);
  } finally { await context.close(); }
}

async function lifecycle(browser, width, locale, theme) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  let response = { state: "ASSIGNED", version: 0, current: null, history: [], can_request: true };
  let removed = false, pending = false, ticket = { id: "internal-ticket", finding_id: finding, credential_id: row.credential_id, version: 1, status: "IN_PROGRESS", template_id: "PUBLIC_EXPOSURE",
    priority: "HIGH", service_impact: "UNKNOWN", responsible_team: "Original team", owner_id: answers.session.id, review_due_at: "2026-10-10T00:00:00Z",
    created_at: "2026-10-01T00:00:00Z", created_by: answers.session.id, updated_by: answers.session.id, steps: [{ code: "SET_FOLLOW_UP", status: "TODO" }] };
  const { context, page, record } = await openConsole(browser, { width, locale, theme, view: "exposed", query: `&id=${encodeURIComponent(row.id)}`, answer: ({ method, endpoint, body }) => {
    if (method === "GET") {
      if (endpoint === "credential-records") return { ...answers[endpoint], items: [{ ...row, owner: { name: "Responder", basis: "ASSIGNED" }, response,
        exposure_state: removed ? "REMOVED" : "ACTIVE", all_locations_removed: removed, removal_pending_location_count: pending ? 1 : 0,
        exposures: row.exposures.map(e => ({ ...e, current: !removed && !pending, removal_pending: pending })) }], total: 1 };
      if (endpoint === `findings/${finding}/response`) return response;
      if (endpoint === `tickets?credential_id=${row.credential_id}&offset=0`) return { mode: "REAL", data: { items: [ticket], next_offset: null } };
      return answers[endpoint];
    }
    if (endpoint === `findings/${finding}/response/ticket`) {
      // A local installation: nothing is sent; the operator records the answer later.
      assert.equal(body.channel, "record"); assert.equal(body.expected_version, 0); assert.equal(body.to, "responder@example.test");
      assert.equal(Object.hasOwn(body, "dm") || Object.hasOwn(body, "slack_channel"), false, "a record names no delivery target");
      response = { state: "WAITING_OWNER", version: 1, can_request: false, current: { request_id: body.request_id, cycle: 1, state: "WAITING_OWNER", channel: "record", ticket: null,
        link_expires_at: null, link_expired: false, assigned_to: body.to,
        requested_by: "00u-unreadable", requested_by_name: "Verified operator", requested_by_email: "operator@example.test", requested_at: "2026-10-01T12:00:00Z" }, history: [] };
      return response;
    }
    if (endpoint === `tickets/${ticket.id}`) {
      assert.equal(body.expected_version, 1, "unsaved edit keeps original revision despite refresh");
      const { refusal } = require("./console-proof.cjs"); return refusal(409, "WORKFLOW_VERSION_CONFLICT");
    }
  } });
  const word = (ko, en) => locale === "ko" ? ko : en;
  try {
    await settled(page, record);
    await page.locator(".drawer").getByRole("tab", { name: word("대응 담당자", "Response owner"), exact: true }).click();
    await page.getByRole("button", { name: word("대응 요청", "Request response"), exact: true }).click();
    const how = page.getByLabel(word("요청 방법", "Send by"));
    assert.deepEqual(await how.locator("option").allTextContents(), [word("기록", "Record")], "a local installation records; it sends no link");
    assert.ok((await page.locator(".drawer-body").textContent()).includes(word("아무것도 보내지 않습니다", "Nothing is sent")));
    await page.getByLabel(word("대응 요청 담당자 이메일", "Responder email")).fill("responder@example.test");
    await page.getByRole("button", { name: word("대응 요청 보내기", "Send response request"), exact: true }).click();
    await settled(page, record);
    assert.ok((await page.locator(".drawer-head").textContent()).includes(word("담당자 회신 대기", "Awaiting response")));
    assert.ok((await page.locator(".drawer-body").textContent()).includes("operator@example.test"));
    assert.ok(!(await page.locator(".drawer-body").textContent()).includes("00u-unreadable"));
    assert.ok(!(await page.locator(".drawer-body").textContent()).includes(word("외부 티켓", "External ticket")), "no ticket fact off the ticket channel");
    assert.equal(await page.getByRole("button", { name: word("대응 다시 요청", "Request response again"), exact: true }).count(), 0, "can_request false: no new request");
    response = { ...response, state: "WAITING_VERIFICATION", version: 2, current: { ...response.current, state: "WAITING_VERIFICATION", answered_at: "2026-10-01T12:01:00Z", received_at: "2026-10-01T12:01:30Z", answered_by: "local" } };
    await page.clock.fastForward(10001); await settled(page, record);
    assert.ok((await page.locator(".drawer-head").textContent()).includes(word("조치 검증 중", "Verifying remediation")));
    pending = true;
    await page.clock.fastForward(10001); await settled(page, record);
    assert.equal(await page.locator(".list-card tbody tr").filter({ hasText: row.hint }).count(), 1, "overlapping source still awaiting reconciliation stays active");
    assert.ok((await page.locator(".list-card tbody tr").textContent()).includes(word("다른 연결의 제거 확인 대기", "Awaiting removal confirmation from other connections")));
    pending = false;
    removed = true; response = { ...response, state: "REMOVED", version: 3, current: { ...response.current, state: "REMOVED", verified_at: "2026-10-01T12:02:00Z" } };
    await page.clock.fastForward(10001); await settled(page, record);
    assert.equal(await page.locator(".list-card tbody tr").filter({ hasText: row.hint }).count(), 0, "removed row leaves default list");
    assert.equal(await page.locator(".drawer").count(), 1, "historical detail stays open");
    await page.getByRole("button", { name: word("상세 닫기", "Close details") }).click();
    await page.getByRole("tab", { name: new RegExp(word("제거 확인된 노출", "Removed exposures")) }).click();
    assert.equal(await page.locator(".list-card tbody tr").filter({ hasText: row.hint }).count(), 1, "removed history is selectable");
    removed = false; response = { ...response, state: "NEEDS_ACTION", version: 4, current: { ...response.current, state: "NEEDS_ACTION" } };
    await page.clock.fastForward(10001); await settled(page, record);
    assert.equal(await page.locator(".list-card tbody tr").filter({ hasText: row.hint }).count(), 0);
    await page.getByRole("tab", { name: new RegExp(word("노출된 Credential", "Exposed credentials")) }).click();
    assert.equal(await page.locator(".list-card tbody tr").filter({ hasText: row.hint }).count(), 1, "recurrence is one stable active row");
    await page.locator(".list-card tbody tr").filter({ hasText: row.hint }).click();
    await page.locator(".drawer").getByRole("tab", { name: new RegExp(`^${word("조치", "Remediation")}`) }).click();
    await settled(page, record);
    await page.locator(".gov-head").click();
    await page.locator(`#gov-team-${ticket.id}`).fill("Unsaved team");
    ticket = { ...ticket, version: 2, responsible_team: "Changed elsewhere" };
    await page.clock.fastForward(10001); await settled(page, record);
    assert.equal(await page.locator(`#gov-team-${ticket.id}`).inputValue(), "Unsaved team", "refresh preserves dirty text");
    await page.locator(".gov-body").getByRole("button", { name: word("저장", "Save"), exact: true }).click();
    await settled(page, record);
    assert.equal(await page.locator(`#gov-team-${ticket.id}`).inputValue(), "Unsaved team", "409 also preserves dirty text");
    await page.locator(".gov-body").getByRole("button", { name: word("최신 내용으로 다시 불러오기", "Reload the latest version") }).click();
    assert.equal(await page.locator(`#gov-team-${ticket.id}`).inputValue(), "Changed elsewhere");
    await inBounds(page, `${width}-${locale}-${theme}`);
    assertClean(record, "response lifecycle");
    assert.equal(record.writes.length, 2);
  } finally { await context.close(); }
}

async function completion(browser, width, locale, theme) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  const word = (ko, en) => locale === "ko" ? ko : en;
  // A local installation's record: the operator's report also records the answer.
  let response = { state: "WAITING_OWNER", version: 3, can_report: true, can_request: false, history: [], current: {
    completion_version: 2, request_id: "00000000-0000-4000-8000-000000000123", cycle: 1, state: "WAITING_OWNER", channel: "record", ticket: null, link_expires_at: null, link_expired: false,
    assigned_to: "owner@example.test", requested_at: "2026-10-01T11:00:00Z", requested_by: "analyst",
  } };
  let removed = false;
  const { context, page, record } = await openConsole(browser, { width, locale, theme, view: "exposed", query: `&id=${encodeURIComponent(row.id)}&dtab=owner`,
    answer({ endpoint, method, body }) {
      if (method === "GET") {
        if (endpoint === "credential-records") return { ...answers[endpoint], items: [{ ...row, response, all_locations_removed: removed, exposure_state: removed ? "REMOVED" : "ACTIVE" }], total: 1 };
        if (endpoint === `findings/${finding}/response`) return response;
        if (endpoint === `findings/${finding}/response/evidence-options?q=`) return { plans: [], entities: [{ id: "00000000-0000-4000-8000-000000000777", label: "replacement key", provider: "aws" }], truncated: false };
        return answers[endpoint];
      }
      if (endpoint === `findings/${finding}/response/report`) {
        assert.equal(body.expected_version, 3); assert.equal(body.request_id, response.current.request_id);
        assert.deepEqual(body.actions, ["REMOVE_PLAINTEXT", "REVOKE"]);
        assert.ok(body.explanation.length >= 20); assert.equal(body.path, "RETIRED");
        response = { ...response, version: 4, state: "WAITING_VERIFICATION", current: { ...response.current, state: "WAITING_VERIFICATION", answer: "APPROVED", answered_by: "local",
          report: { ...body, id: body.report_id, version: 1, hash: "a".repeat(64), by: "local", basis: "LOCAL_OPERATOR_STATEMENT", received_at: "2026-10-01T12:00:00Z" },
          verification: { report: { state: "PASS", reason: "OWNER_REPORT_AND_APPROVAL" }, removal: { state: "WAIT", reason: "COMPLETE_RESCAN_REQUIRED" }, retirement: { state: "WAIT", reason: "ISSUER_RETIREMENT_PROOF_REQUIRED" } },
        } };
        return response;
      }
    } });
  try {
    await settled(page, record);
    const base = await page.locator(".list-card").boundingBox();
    await page.getByRole("button", { name: word("조치 결과 보고", "Report actions"), exact: true }).click();
    const dialog = page.getByRole("dialog");
    assert.ok(await dialog.isVisible());
    const opened = await page.locator(".list-card").boundingBox();
    assert.equal(Math.round(opened.width), Math.round(base.width), "report is an overlay, not a layout column");
    // The console reads replacement choices through its own proxy, for this finding.
    await dialog.getByLabel(word("처리 경로", "Resolution path")).selectOption("REPLACED"); await settled(page, record);
    assert.ok(record.calls.some(call => call.endpoint === `findings/${finding}/response/evidence-options?q=`));
    assert.ok((await dialog.getByLabel(word("교체 작업 또는 새 자격증명", "Rotation or replacement credential")).locator("option").allTextContents()).some(text => text.includes("replacement key")));
    await dialog.getByLabel(word("처리 경로", "Resolution path")).selectOption("RETIRED");
    await dialog.getByLabel(word("노출 위치의 평문 제거", "Remove exposed plaintext"), { exact: true }).check();
    await dialog.getByLabel(word("기존 키 폐기", "Retire old key"), { exact: true }).check();
    await page.locator("#report-explanation").fill("Removed the runbook copy and retired the old token after switching consumers.");
    await page.locator("#report-at").fill("2026-10-01T11:55");
    await inBounds(page, `report-${width}-${locale}`);
    await dialog.getByRole("button", { name: word("보고 기록", "Record report"), exact: true }).click();
    await settled(page, record);
    assert.equal(await page.getByRole("dialog").count(), 0);
    assert.ok((await page.locator(".drawer-head").textContent()).includes(word("조치 검증 중", "Verifying remediation")));
    assert.ok((await page.locator(".drawer-body").textContent()).includes("Removed the runbook copy"));
    removed = true;
    response = { ...response, version: 5, state: "COMPLETED", current: { ...response.current, state: "COMPLETED", completed_at: "2026-10-01T12:01:00Z" } };
    await page.clock.fastForward(10001); await settled(page, record);
    assert.ok((await page.locator(".drawer-head").textContent()).includes(word("조치 완료", "Remediation complete")));
    removed = false;
    response = { ...response, version: 6, state: "NEEDS_ACTION", current: { ...response.current, state: "NEEDS_ACTION", recurred_at: "2026-10-01T12:02:00Z" } };
    await page.clock.fastForward(10001); await settled(page, record);
    assert.ok((await page.locator(".drawer-head").textContent()).includes(word("재조치 필요", "Further action needed")));
    assert.equal(await page.getByRole("button", { name: word("조치 보고 보완", "Supplement action report"), exact: true }).count(), 0);
    assert.equal(record.writes.length, 1, "polling and recurrence never send another request");
    assertClean(record, "completion report");
  } finally { await context.close(); }
}

(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    await refreshHook(browser);
    await lifecycle(browser, 1440, "ko", "light");
    await lifecycle(browser, 360, "en", "dark");
    await completion(browser, 1440, "ko", "light");
    await completion(browser, 360, "en", "dark");
    console.log("PASS live response: save/replace fences stale reads; 10s refresh and 3s preservation; hidden pause/focus; explicit lookup opt-out; request/reply/removal/recurrence; stable dirty ticket/CAS; KO/EN, light/dark, 360px.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
