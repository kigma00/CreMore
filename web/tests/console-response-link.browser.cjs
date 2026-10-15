// Synthetic proof of the response link page (/response): the link's token leaves the address bar and history before
// anything is sent, and only the three /api/response-link endpoints are called (never the console's proxy). The
// person views the request, answers DONE with a replacement picked from evidence-options, and answers INCOMPLETE with
// no actions after a refusal shown in the form; expired, invalid, superseded, not-recipient and closed links each read
// as such. Every answer is made with the keyboard alone, in Korean and English, light and dark, 360 and 1440 wide.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, inBounds, withScreenshot } = require("./console-proof.cjs");
const { themeInitScript, themeStorageKey } = require("./load-theme.cjs");

const app = bundle({ React: "react", client: "react-dom/client", link: "@/console/views/response-link.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const html = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`
  + `<script>${themeInitScript}</script><style>${css}</style></head><body><div id="root"></div>`
  + `<script>${app.preamble}client.createRoot(document.getElementById("root")).render(React.createElement(link.ResponseLinkPage));</script></body></html>`;
const TOKEN = "A".repeat(20) + "b_-" + "9".repeat(20);
const ENTITY = "00000000-0000-4000-8000-000000000777";

// The exact shapes of slackresp-api-report.md §3 (view, and the holder's own report without id, author or basis).
const view = (extra = {}) => ({
  finding: { provider: "aws", credential_type: "AWS_ACCESS_KEY", identifier_hint: "AKIA••••WXYZ", locations: 2 },
  request: { cycle: 1, state: "WAITING_OWNER", requested_at: "2026-10-01T11:00:00Z", link_expires_at: "2026-10-08T11:00:00Z", answer: null, answered_at: null },
  report: null, can_answer: true,
  playbook: {
    ko: [{ title: "IAM 액세스 키 비활성화 후 삭제", steps: ["IAM 콘솔에서 사용자 → 해당 항목 → 보안 자격 증명으로 이동합니다.", "해당 액세스 키를 먼저 비활성화합니다."],
      link: ["AWS IAM 사용자 콘솔", "https://console.aws.amazon.com/iam/home#/users"] }, { title: "새 값을 Vault로 옮기기", steps: ["애플리케이션·CI에는 Vault 경로만 남기고 값은 넣지 않습니다."], link: null }],
    en: [{ title: "Deactivate, then delete the IAM access key", steps: ["In the IAM console, open Users → the matching entry → Security credentials.", "Deactivate the key first."],
      link: ["AWS IAM users console", "https://console.aws.amazon.com/iam/home#/users"] }, { title: "Move the new value into Vault", steps: ["Give applications and CI only the Vault path, never the value."], link: null }] },
  ...extra });
const refusal = (status, code) => ({ status, body: { detail: code, error: code } });
const reportOf = body => ({ result: body.result, path: body.path, actions: body.actions, explanation: body.explanation, performed_at: body.performed_at,
  replacement_plan_id: body.replacement_plan_id ?? null, replacement_entity_id: body.replacement_entity_id ?? null, received_at: "2026-10-01T12:00:00Z", version: 1 });
const answered = (body, state) => ({ ...view().request, state, answer: body.result === "DONE" ? "APPROVED" : "DECLINED", answered_at: "2026-10-01T12:00:00Z" });

async function visit(browser, { locale, theme, width, hash = `#${TOKEN}`, reply }) {
  // UTC and en-US fix what a typed local time means and how the date field takes its digits.
  const context = await browser.newContext({ viewport: { width, height: 900 }, colorScheme: theme === "dark" ? "light" : "dark", timezoneId: "UTC", locale: "en-US" });
  const calls = [], other = [], errors = [];
  await context.addInitScript(({ data, locale, theme, key }) => {
    window.__fixture = data;
    localStorage.setItem("cremore.locale", locale); localStorage.setItem(key, theme);
  }, { data: app.data, locale, theme, key: themeStorageKey });
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin === ORIGIN && url.pathname === "/response") return route.fulfill({ contentType: "text/html; charset=utf-8", body: html });
    if (url.origin === ORIGIN && url.pathname.startsWith("/api/response-link/") && request.method() === "POST") {
      const action = url.pathname.slice("/api/response-link/".length), body = JSON.parse(request.postData() || "null");
      // Where the page was and what it told the server about it, when it sent this.
      calls.push({ action, body, referer: request.headers().referer ?? null });
      const { status = 200, body: answer } = await reply(action, body);
      return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(answer) });
    }
    other.push(url.href); return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(8_000);
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`${ORIGIN}/response${hash}`);
  return { context, page, calls, other, errors };
}

/** Tab (forward) until `target` has the focus: it is reachable from the keyboard. */
async function tabTo(page, target, label) {
  for (let presses = 0; presses < 80; presses++) {
    if (await target.evaluate(el => el === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error(`the keyboard never reached ${label}`);
}

/** 2026-10-01 11:<minute> AM typed into the focused date-time field, segment by segment. Chrome orders the segments by
 * its UI language (pinned to en-US at launch: month/day/year hour:minute AM/PM); the year takes up to six digits, so
 * ArrowRight moves on to the hour. */
async function typeTime(page, minute) {
  await page.keyboard.type("10"); await page.keyboard.type("01"); await page.keyboard.type("2026"); await page.keyboard.press("ArrowRight");
  await page.keyboard.type("11"); await page.keyboard.type(minute); await page.keyboard.type("A");
}

/** The token is gone from the address and the one history entry, and no request named it in a Referer. */
async function tokenGone(page, calls) {
  assert.equal(page.url(), `${ORIGIN}/response`);
  // Every entry this page has in the session history (Navigation API): none holds the token.
  const entries = await page.evaluate(() => [location.hash, navigation.entries().map(entry => entry.url)]);
  assert.deepEqual(entries, ["", [`${ORIGIN}/response`]]);
  assert.ok(!(await page.content()).includes(TOKEN), "the token is never on the page");
  for (const call of calls) { assert.equal(call.referer, null); assert.equal(call.body.token, TOKEN); }
}

function clean(run, label) {
  assert.deepEqual(run.other, [], `${label}: a request off the three link endpoints`);
  assert.deepEqual(run.errors, [], `${label}: a page error`);
}

async function answerDone(browser, combo, word) {
  const run = await visit(browser, { ...combo, reply: (action, body) => {
    if (action === "view") return { body: view() };
    if (action === "evidence-options") return { body: { plans: [], entities: body.q === "repl" ? [{ id: ENTITY, label: "replacement key", provider: "aws" }] : [], truncated: false } };
    if (action === "answer") return { body: view({ report: reportOf(body), request: answered(body, "WAITING_VERIFICATION") }) };
  } });
  const { page, calls } = run;
  try {
    await withScreenshot(page, `response-link-done-${combo.label}`, async () => {
      await page.getByRole("heading", { name: word("노출 자격증명 정리 요청", "Cleanup asked for an exposed credential") }).waitFor();
      await tokenGone(page, calls);
      assert.equal(await page.evaluate(() => document.documentElement.getAttribute("data-theme")), combo.theme);
      const text = await page.locator("main").innerText();
      for (const shown of ["AKIA••••WXYZ", "AWS", word("AWS 액세스 키", "AWS access key"), word("현재 노출 위치", "Current exposed locations"), word("담당자 회신 대기", "Awaiting response"),
        word("조치 방법", "How to fix it"), word("IAM 액세스 키 비활성화 후 삭제", "Deactivate, then delete the IAM access key"), word("새 값을 Vault로 옮기기", "Move the new value into Vault")]) assert.ok(text.includes(shown), shown);
      assert.equal(await page.getByRole("link", { name: word("AWS IAM 사용자 콘솔", "AWS IAM users console") }).getAttribute("href"), "https://console.aws.amazon.com/iam/home#/users");
      await inBounds(page, `link-view-${combo.label}`);
      const report = page.getByRole("button", { name: word("조치 결과 보고", "Report actions"), exact: true });
      await tabTo(page, report, "report"); await page.keyboard.press("Enter");
      const dialog = page.getByRole("dialog");
      await dialog.waitFor();
      const pathField = dialog.getByLabel(word("처리 경로", "Resolution path"));
      await tabTo(page, pathField, "path"); await page.keyboard.press("ArrowDown");
      assert.equal(await pathField.inputValue(), "REPLACED");
      for (const action of [word("노출 위치의 평문 제거", "Remove exposed plaintext"), word("새 키로 교체", "Replace with a new key"), word("교체 키를 금고에 보관", "Store replacement in a vault")]) {
        await tabTo(page, dialog.getByLabel(action, { exact: true }), action); await page.keyboard.press("Space");
      }
      await tabTo(page, dialog.getByLabel(word("발급 항목 검색", "Search inventoried credentials")), "search");
      await page.keyboard.type("repl");
      await tabTo(page, dialog.getByRole("button", { name: word("검색", "Search"), exact: true }), "search button"); await page.keyboard.press("Enter");
      const choice = dialog.getByLabel(word("교체 작업 또는 새 자격증명", "Rotation or replacement credential"));
      await choice.locator("option", { hasText: "replacement key" }).waitFor({ state: "attached" });
      await tabTo(page, choice, "replacement"); await page.keyboard.press("ArrowDown");
      assert.equal(await choice.inputValue(), `entity:${ENTITY}`);
      await tabTo(page, dialog.locator("#report-explanation"), "explanation");
      await page.keyboard.type("Rotated the key, stored the new one in the vault and removed the copy.");
      await tabTo(page, dialog.locator("#report-at"), "performed at"); await typeTime(page, "55");
      assert.equal(await dialog.locator("#report-at").inputValue(), "2026-10-01T11:55");
      await inBounds(page, `link-form-${combo.label}`);
      await tabTo(page, dialog.getByRole("button", { name: word("보고 기록", "Record report"), exact: true }), "submit"); await page.keyboard.press("Enter");
      await page.getByRole("heading", { name: word("회신했습니다", "You answered") }).waitFor();
      assert.equal(await page.getByRole("dialog").count(), 0);
      assert.equal(await page.getByRole("status").innerText(), word("회신을 기록했습니다.", "Your answer is recorded."));
      assert.ok((await page.locator("main").innerText()).includes("Rotated the key"));
      assert.ok((await page.locator("main").innerText()).includes(word("수행 완료", "Done")), "the answer the server recorded is shown");
      assert.equal(await page.getByRole("button", { name: word("조치 보고 보완", "Supplement action report"), exact: true }).count(), 1, "a later answer supplements");
      const answer = calls.find(call => call.action === "answer").body;
      assert.match(answer.report_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      delete answer.report_id;
      assert.deepEqual(answer, { token: TOKEN, result: "DONE", path: "REPLACED", actions: ["REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT"],
        explanation: "Rotated the key, stored the new one in the vault and removed the copy.", performed_at: "2026-10-01T11:55:00.000Z", replacement_entity_id: ENTITY });
      assert.deepEqual(calls.map(call => call.action), ["view", "evidence-options", "evidence-options", "answer"]);
      assert.deepEqual(calls.filter(call => call.action === "evidence-options").map(call => call.body), [{ token: TOKEN }, { token: TOKEN, q: "repl" }]);
      await tokenGone(page, calls);
      clean(run, "done");
    });
  } finally { await run.context.close(); }
}

async function answerIncomplete(browser, combo, word) {
  let refused = false;
  const run = await visit(browser, { ...combo, reply: (action, body) => {
    if (action === "view") return { body: view() };
    if (action === "answer" && !refused) { refused = true; return refusal(422, "RESPONSE_REPORT_TEXT_INVALID"); }  // also a credential in the explanation (§3)
    if (action === "answer") return { body: view({ report: reportOf(body), request: answered(body, "NEEDS_ACTION") }) };
  } });
  const { page, calls } = run;
  try {
    await withScreenshot(page, `response-link-incomplete-${combo.label}`, async () => {
      const report = page.getByRole("button", { name: word("조치 결과 보고", "Report actions"), exact: true });
      await report.waitFor();
      await tabTo(page, report, "report"); await page.keyboard.press("Enter");
      const dialog = page.getByRole("dialog");
      const result = dialog.getByLabel(word("처리 결과", "Result"));
      await tabTo(page, result, "result"); await page.keyboard.press("ArrowDown");
      assert.equal(await result.inputValue(), "INCOMPLETE");
      await tabTo(page, dialog.locator("#report-explanation"), "explanation");
      await page.keyboard.type("The owner team is still migrating the service; nothing changed yet.");
      await tabTo(page, dialog.locator("#report-at"), "performed at"); await typeTime(page, "50");
      const submit = dialog.getByRole("button", { name: word("보고 기록", "Record report"), exact: true });
      assert.equal(await submit.isDisabled(), false, "an incomplete answer needs no action");
      await tabTo(page, submit, "submit"); await page.keyboard.press("Enter");
      // The refusal is said in the form, which keeps the input.
      await dialog.getByRole("alert").waitFor();
      assert.match(await dialog.getByRole("alert").innerText(), word(/비밀값·HTML·숨김 문자는 저장할 수 없습니다/, /without secrets, HTML or hidden characters/));
      assert.equal(await dialog.locator("#report-explanation").inputValue(), "The owner team is still migrating the service; nothing changed yet.");
      await inBounds(page, `link-refused-${combo.label}`);
      await tabTo(page, submit, "submit again"); await page.keyboard.press("Enter");
      await page.getByRole("heading", { name: word("회신했습니다", "You answered") }).waitFor();
      const text = await page.locator("main").innerText();
      assert.ok(text.includes(word("아직 수행한 조치 없음", "No actions performed yet")));
      assert.ok(text.includes(word("추가 조치 필요", "More action needed")));
      assert.ok(text.includes(word("재조치 필요", "Further action needed")));
      const answers = calls.filter(call => call.action === "answer").map(call => call.body);
      assert.equal(answers.length, 2);
      for (const answer of answers) { assert.equal(answer.result, "INCOMPLETE"); assert.equal(answer.path, "RETIRED"); assert.deepEqual(answer.actions, []); }
      assert.equal(answers[0].report_id, answers[1].report_id, "a retry is the same report");
      await tokenGone(page, calls);
      clean(run, "incomplete");
    });
  } finally { await run.context.close(); }
}

async function states(browser, combo, word) {
  const cases = [
    { name: "expired", reply: () => refusal(410, "RESPONSE_LINK_EXPIRED"), head: word("링크가 만료됐습니다", "The link expired"), alert: word(/새 요청/, /new request/) },
    { name: "superseded", reply: () => refusal(404, "RESPONSE_LINK_INVALID"), head: word("쓸 수 없는 링크입니다", "This link cannot be used"), alert: word(/더 새로운 요청/, /newer request/) },
    { name: "cut", hash: `#${TOKEN.slice(1)}`, reply: () => assert.fail("a cut link is never sent"), head: word("쓸 수 없는 링크입니다", "This link cannot be used"), alert: word(/잘렸습니다/, /cut off/) },
    { name: "not recipient", reply: () => refusal(403, "RESPONSE_LINK_NOT_RECIPIENT"), head: word("요청을 받은 사람만 열 수 있습니다", "Only the person asked can open this"), alert: word(/요청을 받은 사람의 회사 계정/, /Only the person the request went to/) },
    { name: "closed", reply: () => ({ body: view({ can_answer: false, request: { ...view().request, state: "COMPLETED" } }) }), head: word("회신을 받지 않는 요청입니다", "This request takes no answer now") },
    { name: "answered", reply: () => ({ body: view({ can_answer: false, report: reportOf({ report_id: "r", result: "DONE", path: "RETIRED", actions: ["REVOKE"], explanation: "Retired the key in the issuer console.", performed_at: "2026-10-01T11:30:00Z" }) }) }), head: word("회신했습니다", "You answered") },
  ];
  for (const item of cases) {
    const run = await visit(browser, { ...combo, hash: item.hash, reply: item.reply });
    try {
      await withScreenshot(run.page, `response-link-${item.name}-${combo.label}`, async () => {
        await run.page.getByRole("heading", { name: item.head }).waitFor();
        if (item.alert) assert.match(await run.page.getByRole("alert").innerText(), item.alert, item.name);
        assert.equal(await run.page.getByRole("button").count(), 0, `${item.name}: nothing to answer`);
        assert.equal(run.page.url(), `${ORIGIN}/response`, `${item.name}: the token left the address`);
        assert.equal(run.calls.length, item.hash ? 0 : 1);
        await inBounds(run.page, `link-${item.name}-${combo.label}`);
        clean(run, item.name);
      });
    } finally { await run.context.close(); }
  }
}

(async () => {
  // The UI language decides the date-time field's segment order (the page's locale does not): pin it.
  const browser = await chromium.launch({ channel: "chrome", headless: true, args: ["--lang=en-US"] });
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [360, 1440]) {
      const combo = { locale, theme, width, label: `${locale}-${theme}-${width}` };
      const word = (ko, en) => locale === "ko" ? ko : en;
      await answerDone(browser, combo, word);
      await answerIncomplete(browser, combo, word);
      await states(browser, combo, word);
    }
    console.log("PASS response link page: the token leaves the address and history first and only /api/response-link is called; view, DONE with an evidence-options replacement, INCOMPLETE with no actions after an inline refusal; expired, superseded, cut, not-recipient, closed and answered links; keyboard only; KO/EN, light/dark, 360/1440.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
