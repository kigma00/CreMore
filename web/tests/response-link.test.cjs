// Exposure-response requests by a CreMore link: the proxy that alone reaches the three public endpoints (never with the
// console's credential), the ways a request can go per installation, the server's can_request on the request button,
// and the words for an expired link, a request that did not go out and each new refusal.
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load } = require("./load-module.cjs");

// The route as built, with its own imports (the shared link-proxy helpers) resolved; only Next's response is stubbed.
function setup(env = { CREMORE_API_URL: "http://127.0.0.1:3302" }) {
  const calls = [];
  // The local admin token is configured, as in a local install: it must never be attached here.
  const api = load("@/app/api/response-link/[action]/route.ts", { overrides: { "next/server": { NextResponse: Response } }, globals: { Headers, Response,
    process: { env: { CREMORE_AUTH_MODE: "local", CREMORE_API_TOKEN: "synthetic-server-only", ...env } },
    fetch: async (url, options) => { calls.push({ url, options }); return Response.json({ can_answer: true }); } } });
  return { api, calls };
}
function post(action, body, headers = {}) {
  const all = Object.fromEntries(Object.entries({ host: "localhost:3301", origin: "http://localhost:3301", ...headers }).filter(([, value]) => value !== undefined));
  const value = new Request(`http://localhost:3301/api/response-link/${action}`, { method: "POST",
    headers: all, body, ...(body instanceof ReadableStream ? { duplex: "half" } : {}) });
  value.nextUrl = new URL(value.url);
  return [value, { params: Promise.resolve({ action }) }];
}
const TOKEN = "A".repeat(20) + "b_-" + "9".repeat(20);

test("the link page's proxy forwards view, answer and evidence-options only, with the person's own sign-in and never the admin token", async () => {
  const { api, calls } = setup();
  const own = "Bearer synthetic-responder-sign-in";
  for (const action of ["view", "answer", "evidence-options"]) {
    const response = await api.POST(...post(action, JSON.stringify({ token: TOKEN }), { authorization: own }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store"); assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  }
  assert.deepEqual(calls.map(call => String(call.url)), ["view", "answer", "evidence-options"].map(action => `http://127.0.0.1:3302/api/v1/response-links/${action}`));
  for (const call of calls) {
    assert.equal(new Headers(call.options.headers).get("authorization"), own);
    assert.equal(call.options.redirect, "error"); assert.equal(call.options.body, JSON.stringify({ token: TOKEN }));
  }
  for (const authorization of [undefined, "Basic a2ltOng=", "Bearer two words", `Bearer ${"x".repeat(17 * 1024)}`]) {
    await api.POST(...post("view", "{}", { authorization }));
    assert.equal(new Headers(calls.at(-1).options.headers).get("authorization"), null, String(authorization).slice(0, 20));
  }
  assert.doesNotMatch(JSON.stringify(calls.map(call => [...new Headers(call.options.headers)])), /synthetic-server-only/);
  for (const action of ["decide", "report", "view/extra", "..", ""]) assert.equal((await api.POST(...post(action, "{}"))).status, 404, action);
  assert.equal(calls.length, 7);
});

test("a cross-site page, a body over 16 KiB or a missing API reaches nothing; a full Korean report fits", async () => {
  const { api, calls } = setup();
  for (const origin of [undefined, "https://attacker.example"]) assert.equal((await api.POST(...post("answer", "{}", { origin }))).status, 403);
  for (const headers of [{}, { "content-length": "2" }]) {
    let cancelled = false;
    const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(6 * 1024)); }, cancel() { cancelled = true; } });
    assert.equal((await api.POST(...post("answer", body, headers))).status, 413); assert.equal(cancelled, true);
  }
  assert.equal((await api.POST(...post("answer", "{}", { "content-length": String(16 * 1024 + 1) }))).status, 413);
  assert.equal(calls.length, 0);
  // 2,000 Korean characters are 6,000 bytes of UTF-8: the report goes on whole.
  const report = JSON.stringify({ token: TOKEN, result: "DONE", path: "RETIRED", actions: ["REMOVE_PLAINTEXT", "REVOKE"], explanation: "가".repeat(2000), performed_at: "2026-10-01T11:55:00.000Z" });
  assert.equal((await api.POST(...post("answer", report))).status, 200);
  assert.equal(calls.at(-1).options.body, report);
  assert.equal((await setup({}).api.POST(...post("view", "{}"))).status, 503);
});

const response = load("@/console/views/credentials/response.tsx");
const data = load("@/console/data.ts");
const en = (ko, english) => english, ko = korean => korean;
const plain = value => JSON.parse(JSON.stringify(value));

test("a request goes by a link only with company sign-in and a ready channel and console address, by record only locally", () => {
  const ready = { mail: true, slack: true, allowed_domains: [], allowed_channels: [], console_url: "https://cremore.example.test" };
  assert.deepEqual(plain(response.responseChannels(true, ready, null)), ["slack", "mail"]);
  assert.deepEqual(plain(response.responseChannels(true, { ...ready, mail: false }, null)), ["slack"]);
  assert.deepEqual(plain(response.responseChannels(true, { ...ready, console_url: null }, null)), [], "no console address: no link can be built");
  assert.deepEqual(plain(response.responseChannels(true, { ...ready, slack: false, mail: false }, "servicedesk")), ["ticket"]);
  assert.deepEqual(plain(response.responseChannels(true, undefined, null)), []);
  // A local installation identifies nobody at a link: the operator records the answer.
  assert.deepEqual(plain(response.responseChannels(false, ready, null)), ["record"]);
  assert.deepEqual(plain(response.responseChannels(false, ready, "servicedesk")), ["record", "ticket"]);
  assert.deepEqual(["slack", "mail", "record", "ticket"].map(channel => response.channelWord(channel, ko)), ["Slack", "메일", "기록", "티켓 시스템"]);
  assert.deepEqual(["slack", "mail", "record", "ticket"].map(channel => response.channelWord(channel, en)), ["Slack", "Mail", "Record", "Ticket system"]);
  assert.match(response.channelNote("slack", en), /Slack DM carries a CreMore link.*7 days/);
  assert.match(response.channelNote("record", ko), /아무것도 보내지 않습니다/);
});

test("an expired link and a request that did not go out read in Korean and English", () => {
  const expired = { link_expires_at: "2026-10-08T12:00:00Z", link_expired: true };
  assert.match(response.linkExpiry(expired, en, "en"), / · Expired · can be requested again$/);
  assert.match(response.linkExpiry(expired, ko, "ko"), / · 만료됨 · 다시 요청할 수 있음$/);
  assert.doesNotMatch(response.linkExpiry({ ...expired, link_expired: false }, en, "en"), /Expired/);
  assert.equal(response.responseLabel("NOT_SENT", en), "Request not sent");
  assert.equal(response.responseLabel("NOT_SENT", ko), "대응 요청 발송 안 됨");
  assert.equal(response.responseTone("NOT_SENT"), "warn");
  assert.equal(response.notSentText("SLACK_USER_NOT_FOUND", en), "The request did not go out, so its link no longer works. Check the cause, then request again. No Slack user has this address.");
  assert.equal(response.notSentText("RESPONSE_SEND_TIMED_OUT", ko).startsWith("대응 요청이 나가지 않아 링크를 무효로 했습니다."), true);
  assert.match(response.notSentText(null, en), /request again\.$/);
});

test("every new refusal has words in both languages, and the GLPI codes are gone", () => {
  const codes = ["RESPONSE_LINK_NEEDS_SIGN_IN", "RESPONSE_LINK_SIGN_IN_REQUIRED", "RESPONSE_LINK_EMAIL_UNVERIFIED", "RESPONSE_LINK_INVALID", "RESPONSE_LINK_EXPIRED",
    "RESPONSE_LINK_NOT_RECIPIENT", "RESPONSE_LINK_CLOSED", "RESPONSE_RECORD_LOCAL_ONLY", "RESPONSE_CONSOLE_URL_NOT_SET", "RESPONSE_RECIPIENT_NOT_A_PERSON",
    "CONTACT_CHANNEL_NOT_SET_UP", "RESPONSE_SEND_TIMED_OUT"];
  for (const code of codes) {
    const korean = data.reasonCodeText(code, ko), english = data.reasonCodeText(code, en);
    assert.notEqual(korean, code, code); assert.notEqual(english, code, code); assert.notEqual(korean, english, code);
  }
  assert.match(data.reasonCodeText("RESPONSE_LINK_EXPIRED", en), /expired/);
  assert.match(data.reasonCodeText("RESPONSE_LINK_NOT_RECIPIENT", ko), /요청을 받은 사람/);
  for (const code of ["GLPI_URL_INVALID", "GLPI_USER_NOT_FOUND", "GLPI_UNAVAILABLE"]) assert.equal(data.reasonCodeText(code, en), code);
});

// The card as the server answers it: the request button follows can_request, never a local list of states.
function card(summary, { contact = { mail: false, slack: true, allowed_domains: [], allowed_channels: [], console_url: "https://cremore.example.test" }, team = true } = {}) {
  const answers = { "ticket-system": { system: null, label: null }, "contact-delivery": contact,
    "findings/finding/response/routing": { version: 1, status: "UNASSIGNED", manual_email_allowed: !team, assignment: null, recommendations: [], targets: [] } };
  const { ResponseCard } = load("@/console/views/credentials/response.tsx", { overrides: {
    "@/console/data": { ...data, useSaved: () => () => {}, useApi: path => ({ data: path === null ? undefined : answers[path], error: null, loading: false, reload() {}, replace() {} }) },
  } });
  const loaded = { data: summary, error: null, loading: false, reload() {}, replace() {} };
  return renderToStaticMarkup(React.createElement(ResponseCard, { c: { finding_id: "finding", owner: null, response: summary }, response: loaded, canEdit: true, admin: false }));
}
const waiting = { request_id: "00000000-0000-4000-8000-000000000001", cycle: 1, state: "WAITING_OWNER", channel: "slack", ticket: null, assigned_to: "person@example.test",
  requested_by: "analyst", requested_at: "2026-10-01T12:00:00Z", link_expires_at: "2026-10-08T12:00:00Z", link_expired: false };

test("the request button follows the server's can_request", () => {
  const again = /<button type="button" class="primary-btn">(대응 다시 요청)<\/button>/;
  assert.doesNotMatch(card({ state: "WAITING_OWNER", version: 2, current: waiting, can_request: false }), /대응 다시 요청/);
  assert.doesNotMatch(card({ state: "WAITING_OWNER", version: 2, current: waiting }), /대응 다시 요청/, "no can_request from the server: no button");
  // A link that expired while the cycle still waits: only the server's word opens a new request.
  const expired = card({ state: "WAITING_OWNER", version: 2, current: { ...waiting, link_expired: true }, can_request: true });
  assert.match(expired, again); assert.match(expired, /만료됨 · 다시 요청할 수 있음/);
  const notSent = card({ state: "NOT_SENT", version: 2, current: { ...waiting, state: "NOT_SENT", error_code: "SLACK_USER_NOT_FOUND" }, can_request: true });
  assert.match(notSent, again); assert.match(notSent, /대응 요청 발송 안 됨/); assert.match(notSent, /Slack에서 이 주소의 사용자를 찾지 못했습니다/);
  assert.doesNotMatch(notSent, /확인 필요: /, "the not-sent reason is said once");
  // The external ticket fact is the ticket channel's only.
  assert.doesNotMatch(expired, /외부 티켓/);
  assert.match(card({ state: "WAITING_OWNER", version: 2, current: { ...waiting, channel: "ticket", ticket: { system: "servicedesk", ticket: "42" } }, can_request: false }), /외부 티켓/);
});

test("a DM that did not go out while the channel notice did is said on the open request", () => {
  // §P2.2 outcome: DM failed, notice ok → WAITING_OWNER with the DM's error_code and the thread.
  const html = card({ state: "WAITING_OWNER", version: 2, can_request: false, current: { ...waiting, error_code: "SLACK_USER_NOT_FOUND",
    thread: { channel_id: "G0PRIVATE01", name: "payments-oncall" }, thread_error: null } });
  assert.match(html, /담당자 회신 대기/);
  assert.match(html, /개인 DM은 나가지 않았고 팀 채널 알림만 갔습니다\. Slack에서 이 주소의 사용자를 찾지 못했습니다\./);
  assert.match(html, /#payments-oncall 채널에 알림 · 진행 상황은 스레드에 기록됨/);
  assert.doesNotMatch(html, /확인 필요: |대응 요청이 나가지 않아/, "neither the generic line nor the not-sent text");
});

test("after the link expired, the partial delivery is history and never claims a working link", () => {
  // The DM's code stays on the cycle after the 7 days; the backend projects it with link_expired: true.
  const html = card({ state: "WAITING_OWNER", version: 3, can_request: true, current: { ...waiting, link_expired: true, error_code: "SLACK_USER_NOT_FOUND",
    thread: { channel_id: "G0PRIVATE01", name: "payments-oncall" }, thread_error: null } });
  assert.match(html, /개인 DM은 나가지 않았고 팀 채널 알림만 갔습니다\./);
  assert.match(html, /만료됨 · 다시 요청할 수 있음/);
  assert.doesNotMatch(html, /쓸 수 있습니다|링크는 사용|link works/, "nothing says the expired link works");
  assert.match(html, /<button type="button" class="primary-btn">대응 다시 요청<\/button>/);
});

test("with no way to send, the button waits and says what an admin sets up", () => {
  const none = card({ state: "NEW", version: 0, current: null, can_request: true }, { contact: { mail: false, slack: false, allowed_domains: [], allowed_channels: [] } });
  assert.match(none, /<button type="button" class="primary-btn" disabled="">대응 요청<\/button>/);
  assert.match(none, /Slack 또는 메일과 콘솔 주소를 설정하면/);
  const local = card({ state: "NEW", version: 0, current: null, can_request: true }, { team: false, contact: { mail: false, slack: false, allowed_domains: [], allowed_channels: [] } });
  assert.match(local, /<button type="button" class="primary-btn">대응 요청<\/button>/, "a local installation can always record");
});

test("an expired link offers no report, a request that did not go out shows no live expiry, and the mail note reads right", () => {
  // Past the link's end the server refuses every report (410): the card does not offer one.
  const expired = card({ state: "WAITING_OWNER", version: 3, can_request: true, can_report: true, current: { ...waiting, completion_version: 2, link_expired: true } });
  assert.doesNotMatch(expired, /조치 결과 보고|조치 보고 보완/);
  const open = card({ state: "WAITING_OWNER", version: 3, can_request: false, can_report: true, current: { ...waiting, completion_version: 2 } });
  assert.match(open, /조치 결과 보고/, "control: an open link still offers the report");
  // A send that did not go out keeps link.expires_at, but its link is dead: no expiry date beside "Not sent".
  const notSent = card({ state: "NOT_SENT", version: 2, can_request: true, current: { ...waiting, state: "NOT_SENT", error_code: "SLACK_USER_NOT_FOUND" } });
  assert.doesNotMatch(notSent, /링크 만료/);
  assert.match(card({ state: "WAITING_OWNER", version: 2, can_request: false, current: waiting }), /링크 만료/, "control: a live link shows its expiry");
  assert.match(response.channelNote("mail", ko), /^메일로 CreMore 링크를/);
  assert.match(response.channelNote("slack", ko), /^Slack DM으로 CreMore 링크를/);
});

test("a thread Slack locked or made read-only reads as one sentence, and the other thread codes have words", () => {
  for (const code of ["SLACK_RESTRICTED_ACTION_THREAD_LOCKED", "SLACK_RESTRICTED_ACTION_READ_ONLY_CHANNEL", "SLACK_RESTRICTED_ACTION"]) {
    assert.doesNotMatch(response.threadErrorText(code, ko), /SLACK_/);
    assert.match(response.threadErrorText(code, en), /does not allow posting in that channel or thread/);
  }
  for (const code of ["CONTACT_SEND_ERROR", "SLACK_IS_ARCHIVED", "SLACK_MSG_TOO_LONG", "SLACK_THREAD_NOT_FOUND", "SLACK_CANNOT_REPLY_TO_MESSAGE"]) {
    assert.doesNotMatch(response.threadErrorText(code, ko), new RegExp(code), `${code} in Korean`);
    assert.doesNotMatch(response.threadErrorText(code, en), new RegExp(code), `${code} in English`);
  }
});
