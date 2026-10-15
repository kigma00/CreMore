// Team channels for exposure-response requests (phase 2), in the real console with synthetic answers, by keyboard only:
// the Admin's "Response channels" editor (pick a channel the bot can see, allow a public one, add by ID, a server
// refusal, then a save), a request to a channel plus the person's DM with the channel prefilled from the routing
// recommendation, and a channel-only request that did not go out (200, NOT_SENT). The cycle shows the channel and a
// thread problem. Korean and English, light and dark, 360 and 1440 wide.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, withScreenshot, refusal } = require("./console-proof.cjs");

const PRIVATE = { channel_id: "G0PRIVATE01", name: "payments-oncall", is_private: true };
const PUBLIC = { channel_id: "C0PUBLIC001", name: "security-open", is_private: false };
const EXTERNAL = { channel_id: "C0PARTNER01", name: "partner-shared", is_private: false, is_ext_shared: true };
const PERSON_REF = "00000000-0000-4000-8000-000000000501";
const PERSON = { id: PERSON_REF, person_ref: PERSON_REF, name: "Pat Kim", email: "pat@example.test", department: "Payments", title: null,
  state: "ACTIVE", sources: [], selectable: true, reason: null };
const OTHER_REF = "00000000-0000-4000-8000-000000000502";
const OTHER = { ...PERSON, id: OTHER_REF, person_ref: OTHER_REF, name: "Sam Lee", email: "sam@example.test", department: "Security" };
const READY = { mail: false, slack: true, allowed_domains: ["example.test"], allowed_channels: [], console_url: "https://cremore.example.test" };

/** Tab (Shift+Tab when `back`) until `target` has the focus: it is reachable from the keyboard. */
async function tabTo(page, target, label, back = false) {
  for (let presses = 0; presses < 400; presses++) {
    if (await target.evaluate(el => el === document.activeElement).catch(() => false)) return;
    await page.keyboard.press(back ? "Shift+Tab" : "Tab");
  }
  throw new Error(`the keyboard never reached ${label}`);
}

async function editor(browser, combo, word) {
  const answers = preview();
  answers.session.auth_mode = "oidc";
  let saved = { version: 4, channels: [{ ...PRIVATE, allow_public: false, checked_at: "2026-10-01T12:00:00Z" }] };
  const puts = [];
  const { context, page, record } = await openConsole(browser, { ...combo, view: "sources", answer: ({ method, endpoint, body }) => {
    if (method === "GET") {
      if (endpoint === "settings/response-channels") return saved;
      if (endpoint === "settings/response-channels/candidates") return { channels: [EXTERNAL, { ...PRIVATE, is_ext_shared: false }, { ...PUBLIC, is_ext_shared: false }], truncated: false };
      if (endpoint === "response-channels") return { channels: saved.channels.map(({ channel_id, name, is_private }) => ({ channel_id, name, is_private })) };
      return answers[endpoint];
    }
    if (endpoint === "settings/response-channels" && method === "PUT") {
      puts.push(body);
      // The server checks each channel with Slack: the one typed by ID turns out to be shared with another company.
      if (body.channels.some(item => item.channel_id === "C0EXTRA0001")) return refusal(422, "RESPONSE_CHANNEL_EXTERNAL");
      saved = { version: 5, channels: [{ ...PRIVATE, allow_public: false, checked_at: "2026-10-02T09:00:00Z" }, { ...PUBLIC, allow_public: true, checked_at: "2026-10-02T09:00:00Z" }] };
      return saved;
    }
  } });
  try {
    await withScreenshot(page, `channels-editor-${combo.label}`, async () => {
      await settled(page, record);
      const card = page.locator("button.ig-other", { hasText: word("대응 알림 채널", "Response channels") });
      assert.match(await card.innerText(), word(/1개 채널/, /1 channel/));
      await tabTo(page, card, "the Response channels card"); await page.keyboard.press("Enter");
      const dialog = page.getByRole("dialog"); await settled(page, record);
      const text = await dialog.innerText();
      assert.ok(text.includes("#partner-shared") && text.includes(word("외부 공유 · 거절됨", "Externally shared · refused")), "an external channel shows as refused");
      const pick = dialog.getByLabel(word("봇이 볼 수 있는 채널", "Channels the bot can see"));
      assert.deepEqual(await pick.locator("option").evaluateAll(options => options.map(option => option.value)), ["", PUBLIC.channel_id], "only an unlisted, unshared channel can be picked");
      await tabTo(page, pick, "the channel picker"); await page.keyboard.press("ArrowDown");
      assert.equal(await pick.inputValue(), PUBLIC.channel_id);
      await tabTo(page, dialog.getByRole("button", { name: word("추가", "Add"), exact: true }), "add"); await page.keyboard.press("Enter");
      const privateRow = dialog.locator(".card", { hasText: "#payments-oncall" }), publicRow = dialog.locator(".card", { hasText: "#security-open" });
      assert.equal(await privateRow.getByRole("checkbox").isDisabled(), true, "a private channel takes no public allow");
      assert.ok((await publicRow.innerText()).includes(word("공개 채널은 워크스페이스의 누구나", "Anyone in the workspace can read a public channel")));
      await tabTo(page, publicRow.getByRole("checkbox"), "the public allow"); await page.keyboard.press("Space");
      assert.equal(await publicRow.getByRole("checkbox").isChecked(), true);
      const typed = dialog.getByLabel(word("또는 채널 ID", "Or a channel ID"));
      await tabTo(page, typed, "the channel ID field"); await page.keyboard.type("c0extra0001");
      await tabTo(page, dialog.getByRole("button", { name: word("ID로 추가", "Add by ID"), exact: true }), "add by ID"); await page.keyboard.press("Enter");
      assert.ok((await dialog.innerText()).includes(word("저장할 때 확인", "Checked on save")));
      const save = dialog.getByRole("button", { name: word("저장", "Save"), exact: true });
      await tabTo(page, save, "save"); await page.keyboard.press("Enter"); await settled(page, record);
      assert.ok((await dialog.innerText()).includes(word("외부 회사와 공유된 Slack 채널에는 올리지 않습니다.", "A Slack channel shared with another company is never used.")), "the server's refusal is said");
      await inBounds(page, `channels-refused-${combo.label}`);
      await tabTo(page, dialog.getByRole("button", { name: word("C0EXTRA0001 빼기", "Remove C0EXTRA0001") }), "remove"); await page.keyboard.press("Enter");
      await tabTo(page, save, "save again"); await page.keyboard.press("Enter"); await settled(page, record);
      assert.equal(await save.isDisabled(), true, "saved: nothing left to save");
      assert.deepEqual(puts, [
        { expected_version: 4, channels: [{ channel_id: PRIVATE.channel_id, allow_public: false }, { channel_id: PUBLIC.channel_id, allow_public: true }, { channel_id: "C0EXTRA0001", allow_public: false }] },
        { expected_version: 4, channels: [{ channel_id: PRIVATE.channel_id, allow_public: false }, { channel_id: PUBLIC.channel_id, allow_public: true }] },
      ]);
      await inBounds(page, `channels-saved-${combo.label}`);
      assertClean(record, "response channels editor");
    });
  } finally { await context.close(); }
}

async function request(browser, combo, word, { dm }) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  answers.session.auth_mode = "oidc";
  let state = { state: "ASSIGNED", version: 0, current: null, history: [], can_request: true };
  const posts = [];
  const cycle = body => ({ request_id: body.request_id, cycle: 1, channel: "slack", ticket: null, assigned_to: PERSON.email, recipient: PERSON, team: body.team,
    requested_by: "operator", requested_at: "2026-10-01T12:00:00Z", link_expired: false });
  // §P2.2 routing: each RESPONSIBILITY_RULE recommendation names its slack_channel; the top-level slack_channel is the one
  // channel the finding's rules name, null when they name several.
  const routing = dm
    ? { slack_channel: null, recommendations: [{ person: PERSON, basis: "RESPONSIBILITY_RULE", team: "Payments", slack_channel: PRIVATE },
      { person: OTHER, basis: "RESPONSIBILITY_RULE", team: "Security", slack_channel: PUBLIC }] }
    : { slack_channel: PRIVATE, recommendations: [{ person: PERSON, basis: "RESPONSIBILITY_RULE", team: "Payments", slack_channel: PRIVATE },
      { person: OTHER, basis: "VERIFIED_EMAIL", team: "Security" }] };
  const { context, page, record } = await openConsole(browser, { ...combo, view: "exposed", query: `&id=${encodeURIComponent(row.id)}&dtab=owner`, answer: ({ method, endpoint, body }) => {
    if (method === "GET") {
      if (endpoint === `findings/${finding}/response`) return state;
      if (endpoint === `findings/${finding}/response/routing`) return { version: 2, status: "READY", manual_email_allowed: false, assignment: null, targets: [], ...routing };
      if (endpoint === "contact-delivery") return READY;
      if (endpoint === "response-channels") return { channels: [PRIVATE, PUBLIC] };
      return answers[endpoint];
    }
    if (endpoint === `findings/${finding}/response/ticket`) {
      posts.push(body);
      // DM failed, channel notice delivered: still open, the DM's code and the thread.
      if (dm) state = { state: "WAITING_OWNER", version: 1, can_request: false, history: [], current: { ...cycle(body), state: "WAITING_OWNER", link_expires_at: "2026-10-08T12:00:00Z",
        thread: { channel_id: PRIVATE.channel_id, name: PRIVATE.name }, thread_error: null, error_code: "SLACK_USER_NOT_FOUND" } };
      // The channel changed since approval: refused whole, nothing stored or sent.
      else if (posts.length === 1) return refusal(409, "RESPONSE_CHANNEL_ARCHIVED");
      // The notice was the only delivery and its post failed: 200, NOT_SENT, the link dead.
      else state = { state: "NOT_SENT", version: 1, can_request: true, history: [], current: { ...cycle(body), state: "NOT_SENT", link_expires_at: null, thread: null,
        thread_error: "SLACK_NOT_IN_CHANNEL", error_code: "SLACK_NOT_IN_CHANNEL" } };
      return state;
    }
  } });
  try {
    await withScreenshot(page, `channels-request-${dm ? "dm" : "only"}-${combo.label}`, async () => {
      await settled(page, record);
      await tabTo(page, page.getByRole("button", { name: word("대응 요청", "Request response"), exact: true }), "request"); await page.keyboard.press("Enter");
      const drawer = page.locator(".drawer");
      const channel = drawer.getByLabel(word("팀 Slack 채널에도 알림", "Also post in a team Slack channel"));
      assert.equal(await channel.inputValue(), dm ? "" : PRIVATE.channel_id, dm ? "several rule channels: none before a person is chosen" : "prefilled from routing.slack_channel");
      const toPerson = drawer.getByLabel(word("개인 DM도 보내기", "Also DM the person"));
      assert.equal(await toPerson.isChecked(), true, "the DM is on by default");
      const pat = drawer.getByRole("button", { name: /pat@example\.test/ }), sam = drawer.getByRole("button", { name: /sam@example\.test/ });
      // The channel follows the recommendation chosen: Sam's rule channel (or none), then Pat's.
      await tabTo(page, sam, "the second recommended person"); await page.keyboard.press("Enter");
      assert.equal(await channel.inputValue(), dm ? PUBLIC.channel_id : "", "choosing Sam takes Sam's channel, never Pat's");
      await tabTo(page, pat, "the first recommended person", true); await page.keyboard.press("Enter");
      assert.equal(await channel.inputValue(), PRIVATE.channel_id, "choosing Pat takes Pat's channel");
      const submit = drawer.getByRole("button", { name: word("대응 요청 보내기", "Send response request"), exact: true });
      if (!dm) {
        await tabTo(page, toPerson, "the DM toggle"); await page.keyboard.press("Space");
        assert.equal(await toPerson.isChecked(), false);
        await tabTo(page, channel, "the channel"); await page.keyboard.press("ArrowUp");
        assert.equal(await channel.inputValue(), "");
        const hint = word("보낼 곳을 하나 이상 고르세요", "Choose at least one place to send it");
        assert.ok((await drawer.innerText()).includes(hint)); assert.equal(await submit.isDisabled(), true, "no target: nothing can be sent");
        await inBounds(page, `channels-no-target-${combo.label}`);
        await page.keyboard.press("ArrowDown");
        assert.equal(await channel.inputValue(), PRIVATE.channel_id);
        assert.ok(!(await drawer.innerText()).includes(hint));
        // A channel chosen by hand stays when the person changes.
        await tabTo(page, sam, "Sam again"); await page.keyboard.press("Enter");
        assert.equal(await channel.inputValue(), PRIVATE.channel_id, "an explicit channel is kept");
        await tabTo(page, pat, "Pat again", true); await page.keyboard.press("Enter");
      }
      await tabTo(page, submit, "send"); await page.keyboard.press("Enter"); await settled(page, record);
      const body = async () => await drawer.locator(".drawer-body").innerText();
      if (!dm) {
        // 409: the form says why and keeps everything; nothing changed on the case.
        assert.match(await drawer.getByRole("alert").filter({ hasText: word("보관된", "archived") }).innerText(), word(/보관된 Slack 채널에는 올리지 않습니다/, /An archived Slack channel is not used/));
        assert.equal(await channel.inputValue(), PRIVATE.channel_id); assert.equal(await toPerson.isChecked(), false);
        assert.equal(state.state, "ASSIGNED"); assert.equal(await submit.isDisabled(), false, "the draft stays ready to send again");
        assert.ok((await drawer.locator(".card", { hasText: word("대응 진행", "Response progress") }).innerText()).includes(word("담당자 지정됨", "Assigned")), "the case did not move");
        await inBounds(page, `channels-refused-request-${combo.label}`);
        await tabTo(page, submit, "send again"); await page.keyboard.press("Enter"); await settled(page, record);
      }
      assert.equal(posts.length, dm ? 1 : 2);
      for (const post of posts) assert.deepEqual({ channel: post.channel, person_ref: post.person_ref, team: post.team, dm: post.dm, slack_channel: post.slack_channel },
        { channel: "slack", person_ref: PERSON_REF, team: "Payments", dm, slack_channel: PRIVATE.channel_id });
      if (dm) {
        assert.ok((await page.locator(".drawer-head").innerText()).includes(word("담당자 회신 대기", "Awaiting response")));
        assert.ok((await body()).includes(word("#payments-oncall 채널에 알림 · 진행 상황은 스레드에 기록됨", "Posted in #payments-oncall · progress goes to its thread")));
        assert.ok((await body()).includes(word("개인 DM은 나가지 않았고 팀 채널 알림만 갔습니다. Slack에서 이 주소의 사용자를 찾지 못했습니다.",
          "The DM to the person did not go out; only the team channel notice did. No Slack user has this address.")), "the DM failure is said on the open request");
        // The thread job later finds the channel turned public without the Admin's allow.
        state = { ...state, version: 2, current: { ...state.current, thread_error: "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED" } };
        await page.clock.fastForward(10001); await settled(page, record);
        assert.ok((await body()).includes(word("팀 채널 알림 문제: 공개 채널입니다.", "Team channel notice problem: This is a public channel.")));
        // Seven days on, unanswered: the code stays as delivery history beside the expiry, never as a working link.
        state = { ...state, version: 3, can_request: true, current: { ...state.current, link_expired: true } };
        await page.clock.fastForward(10001); await settled(page, record);
        assert.ok((await body()).includes(word("만료됨 · 다시 요청할 수 있음", "Expired · can be requested again")));
        assert.ok((await body()).includes(word("개인 DM은 나가지 않았고 팀 채널 알림만 갔습니다.", "The DM to the person did not go out; only the team channel notice did.")));
        assert.doesNotMatch(await body(), word(/쓸 수 있습니다/, /link works/));
      } else {
        assert.ok((await page.locator(".drawer-head").innerText()).includes(word("대응 요청 발송 안 됨", "Request not sent")), "a 200 NOT_SENT reads as not sent");
        assert.ok((await body()).includes(word("봇이 그 채널에 들어가 있지 않습니다.", "The bot is not in that channel.")));
        assert.equal(await page.getByRole("button", { name: word("대응 다시 요청", "Request response again"), exact: true }).count(), 1);
      }
      await inBounds(page, `channels-cycle-${dm ? "dm" : "only"}-${combo.label}`);
      assertClean(record, `request ${dm ? "with DM" : "channel only"}`);
    });
  } finally { await context.close(); }
}

(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [360, 1440]) {
      const combo = { locale, theme, width, label: `${locale}-${theme}-${width}` };
      const word = (ko, en) => locale === "ko" ? ko : en;
      await editor(browser, combo, word);
      await request(browser, combo, word, { dm: true });
      await request(browser, combo, word, { dm: false });
    }
    console.log("PASS response channels: Admin editor (external refused, pick, public allow only on a public channel, add by ID, server refusal, save); channel bound to the chosen person's rule (routing.slack_channel before a choice); channel plus DM (DM failed, notice delivered: open with the DM's code and the thread); channel only (no-target guard, 409 refusal kept in the form, then 200 NOT_SENT); thread problem; keyboard only; KO/EN, light/dark, 360/1440.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
