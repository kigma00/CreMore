// Team channels for exposure-response requests (phase 2): the Admin editor allows a public channel only when Slack said
// it is public and refuses channels shared with another company; a request needs at least one target; the channel is
// prefilled from the routing recommendation; the cycle's thread and every new code read in Korean and English.
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load } = require("./load-module.cjs");

const data = load("@/console/data.ts");
const response = load("@/console/views/credentials/response.tsx");
const en = (ko, english) => english, ko = korean => korean;
const plain = value => JSON.parse(JSON.stringify(value));

const PRIVATE = { channel_id: "G0PRIVATE01", name: "payments-oncall", is_private: true, allow_public: false, checked_at: "2026-10-01T12:00:00Z" };
const PUBLIC = { channel_id: "C0PUBLIC001", name: "security-open", is_private: false, allow_public: true, checked_at: "2026-10-01T12:00:00Z" };
const EXTERNAL = { channel_id: "C0PARTNER01", name: "partner-shared", is_private: false, is_ext_shared: true };
const OPEN = { channel_id: "C0OPEN00001", name: "platform-team", is_private: true, is_ext_shared: false };

function editor(channels) {
  const answers = { "settings/response-channels": { version: 3, channels }, "settings/response-channels/candidates": { channels: [EXTERNAL, OPEN] } };
  const { ResponseChannelsModal } = load("@/console/views/integrations/response-channels.tsx", { overrides: {
    "@/console/data": { ...data, useSaved: () => () => {}, useApi: path => ({ data: answers[path], error: null, loading: false, reload() {}, replace() {} }) },
    "@/console/layer": { Modal: ({ children }) => React.createElement("div", { role: "dialog" }, children), useToast: () => () => {} },
  } });
  return renderToStaticMarkup(React.createElement(ResponseChannelsModal, { onClose() {} }));
}

test("the editor offers the public allow only on a channel Slack said is public, with its warning", () => {
  const html = editor([PRIVATE, PUBLIC]);
  const boxes = [...html.matchAll(/<input type="checkbox"[^>]*>/g)].map(match => match[0]);
  assert.equal(boxes.length, 2);
  assert.match(boxes[0], /disabled=""/, "a private channel takes no public allow");
  assert.doesNotMatch(boxes[1], /disabled/, "a public channel can be allowed");
  assert.match(boxes[1], /checked=""/);
  assert.equal(html.match(/공개 채널은 워크스페이스의 누구나 읽을 수 있습니다/g)?.length, 1, "the warning sits on the public row only");
  assert.match(html, /#payments-oncall/); assert.match(html, /#security-open/);
});

test("a channel shared with another company is shown as refused and never offered", () => {
  const html = editor([]);
  assert.match(html, /#partner-shared<\/span><span class="igs warn"><span class="dot"><\/span>외부 공유 · 거절됨/);
  const options = [...html.matchAll(/<option value="([^"]*)"/g)].map(match => match[1]);
  assert.deepEqual(options, ["", OPEN.channel_id], "only the shared-with-nobody channel can be picked");
  assert.match(html, /아직 없습니다/);
});

test("a link request needs the person's DM or a team channel; record and ticket name neither", () => {
  assert.deepEqual(plain(response.deliveryTargets("slack", true, "")), { dm: true }, "no channel: no slack_channel key");
  assert.deepEqual(plain(response.deliveryTargets("slack", true, "G0PRIVATE01")), { dm: true, slack_channel: "G0PRIVATE01" });
  assert.deepEqual(plain(response.deliveryTargets("slack", false, "G0PRIVATE01")), { dm: false, slack_channel: "G0PRIVATE01" }, "channel only");
  assert.equal(response.deliveryTargets("slack", false, ""), null, "nowhere to send");
  assert.equal(response.deliveryTargets("mail", false, ""), null);
  assert.deepEqual(plain(response.deliveryTargets("mail", false, "G0PRIVATE01")), { dm: false, slack_channel: "G0PRIVATE01" });
  for (const channel of ["record", "ticket"]) assert.deepEqual(plain(response.deliveryTargets(channel, false, "G0PRIVATE01")), {}, channel);
});

test("the team channel is prefilled from the routing recommendation while it is still approved", () => {
  const channel = (channel_id, name = "x") => ({ channel_id, name, is_private: true });
  const approved = [{ channel_id: "G0PRIVATE01", name: "payments-oncall", is_private: true }, { channel_id: "C0PUBLIC001", name: "security-open", is_private: false }];
  // Two people, each with their own rule's channel (slack_channel, as GET …/routing gives it): the channel follows the
  // person chosen, never another person's.
  const two = { slack_channel: null, recommendations: [{ person: { person_ref: "A" }, basis: "RESPONSIBILITY_RULE", slack_channel: channel("G0PRIVATE01") },
    { person: { person_ref: "B" }, basis: "RESPONSIBILITY_RULE", slack_channel: channel("C0PUBLIC001") }, { person: { person_ref: "N" }, basis: "VERIFIED_EMAIL" },
    { person: { person_ref: "G" }, basis: "RESPONSIBILITY_RULE", slack_channel: channel("C0GONE00001") }] };
  assert.equal(response.recommendedChannel(two, approved, "B"), "C0PUBLIC001");
  assert.equal(response.recommendedChannel(two, approved, "A"), "G0PRIVATE01");
  assert.equal(response.recommendedChannel(two, approved, "N"), "", "a person recommended without a channel gets none");
  assert.equal(response.recommendedChannel(two, approved, "G"), "", "a channel no longer approved is skipped");
  assert.equal(response.recommendedChannel(two, approved, "someone-else"), "", "a person not recommended gets none");
  // Before anyone is chosen: the one channel the finding's rules name (null when they name several), while approved.
  assert.equal(response.recommendedChannel(two, approved), "", "several rule channels: none until a person is chosen");
  assert.equal(response.recommendedChannel({ ...two, slack_channel: channel("G0PRIVATE01") }, approved), "G0PRIVATE01");
  assert.equal(response.recommendedChannel({ ...two, slack_channel: channel("C0GONE00001") }, approved), "");
  assert.equal(response.recommendedChannel({ recommendations: [] }, approved), "", "an older answer without slack_channel");
});

test("a typed channel ID is taken in the shape the server takes", () => {
  const { CHANNEL_ID } = load("@/console/views/integrations/response-channels.tsx");
  for (const id of ["C01234567", "G0PRIVATE01", "C0123456789AB"]) assert.equal(CHANNEL_ID.test(id), true, id);
  for (const id of ["C0123456", "C0123456789ABC", "D0123456789", "c0123456789", "C0123-45678"]) assert.equal(CHANNEL_ID.test(id), false, id);
});

test("the cycle's team channel and a thread problem read in Korean and English", () => {
  assert.equal(response.threadText({ channel_id: "G0PRIVATE01", name: "payments-oncall" }, ko), "#payments-oncall 채널에 알림 · 진행 상황은 스레드에 기록됨");
  assert.equal(response.threadText({ channel_id: "G0PRIVATE01", name: "payments-oncall" }, en), "Posted in #payments-oncall · progress goes to its thread");
  assert.equal(response.threadErrorText("RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED", en), "Team channel notice problem: This is a public channel. An admin must allow it as public under Response channels first.");
  assert.match(response.threadErrorText("RESPONSE_CHANNEL_EXTERNAL", ko), /^팀 채널 알림 문제: 외부 회사와 공유된/);
  assert.equal(response.dmFailedText("slack", "SLACK_USER_NOT_FOUND", en), "The DM to the person did not go out; only the team channel notice did. No Slack user has this address.");
  assert.match(response.dmFailedText("mail", "SMTP_RECIPIENTS_REFUSED", ko), /^개인 메일은 나가지 않았고 팀 채널 알림만 갔습니다\. 메일 서버가/);
  for (const say of [ko, en]) assert.doesNotMatch(response.dmFailedText("slack", "SLACK_USER_NOT_FOUND", say), /쓸 수 있습니다|works/, "delivery history only, no link claim");
});

test("every new channel code has words in both languages", () => {
  for (const code of ["RESPONSE_CHANNEL_NOT_FOUND", "RESPONSE_CHANNEL_ARCHIVED", "RESPONSE_CHANNEL_EXTERNAL", "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED",
    "RESPONSE_CHANNEL_NOT_APPROVED", "SLACK_SCOPE_MISSING", "RESPONSE_CHANNELS_CHANGED", "RESPONSE_CHANNELS_INVALID", "RESPONSE_SLACK_CHANNEL_NOT_ALLOWED", "RESPONSE_DELIVERY_REQUIRED"]) {
    const korean = data.reasonCodeText(code, ko), english = data.reasonCodeText(code, en);
    assert.notEqual(korean, code, code); assert.notEqual(english, code, code); assert.notEqual(korean, english, code);
  }
  assert.match(data.reasonCodeText("SLACK_SCOPE_MISSING", en), /channels:read and groups:read/);
});
