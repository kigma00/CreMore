// Slack detection alerts in Settings: how delivery stands in one line, every refusal and delivery code in words, the
// webhook address checked before it is sent and never shown back, and the card mounted where the API it saves to is.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const alerts = load("@/console/views/settings-alerts.tsx");
const data = load("@/console/data.ts");
const locale = load("@/components/locale.tsx");
const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
const plain = value => JSON.parse(JSON.stringify(value));  // out of the module's own realm
const en = (ko, english) => english;
const ko = (korean) => korean;
const NOW = Date.parse("2026-10-09T05:00:00Z");
const status = { pending: 0, oldest_pending_at: null, last_seen_at: "2026-10-09T04:59:30Z", last_success_at: "2026-10-09T04:58:00Z",
  last_failure_at: null, last_error_code: null, consecutive_failures: 0 };
const view = (changes = {}, state = {}) => ({ enabled: true, transport: "webhook", webhook_saved: true, channel: null, channels: [],
  bot_ready: false, min_severity: "INFO", detail: "standard", language: "ko", events: [], console_url: null, enabled_at: null,
  updated_by: null, updated_at: null, ...changes, status: { ...status, ...state } });

test("delivery reads as one line, and a line that needs a look says so", () => {
  assert.deepEqual(plain(alerts.deliveryState(view({ enabled: false }), en, "en", NOW)), { text: "Off · once on, detections from then on are sent.", warn: false });
  const working = alerts.deliveryState(view(), en, "en", NOW);
  assert.equal(working.warn, false);
  assert.match(working.text, /^Working · last sent /);
  assert.match(alerts.deliveryState(view({}, { last_success_at: null, pending: 3 }), en, "en", NOW).text, /^Working · no alert sent yet · 3 waiting$/);
  // The worker never looked, or stopped looking two minutes ago: both are said.
  assert.deepEqual(plain(alerts.deliveryState(view({}, { last_seen_at: null }), en, "en", NOW)), { text: "The worker has not picked the alerts up yet.", warn: true });
  const stale = alerts.deliveryState(view({}, { last_seen_at: "2026-10-09T04:50:00Z" }), en, "en", NOW);
  assert.equal(stale.warn, true);
  assert.match(stale.text, /^The worker has not checked the alerts since /);
  const failing = alerts.deliveryState(view({}, { consecutive_failures: 2, last_error_code: "DELIVERY_RATE_LIMITED", pending: 4 }), en, "en", NOW);
  assert.equal(failing.warn, true);
  assert.equal(failing.text, "Not sent; retrying (2 in a row): Slack's rate limit was reached. Every alert resumes after the time Slack gave. · 4 waiting");
  assert.match(alerts.deliveryState(view({}, { consecutive_failures: 1, last_error_code: "AUTH_FAILED" }), ko, "ko", NOW).text, /^보내지 못해 다시 보냅니다\(연속 1회\): /);
});

test("every code reads as words in both languages, and others fall back to the console's reasons", () => {
  for (const code of ["ALERTS_WEBHOOK_INVALID", "ALERTS_WEBHOOK_REQUIRED", "ALERTS_CHANNEL_REQUIRED", "ALERTS_CHANNEL_NOT_ALLOWED",
    "ALERTS_BOT_NOT_SET_UP", "ALERTS_NOT_CONFIGURED", "ALERTS_SECRET_UNAVAILABLE", "DELIVERY_RATE_LIMITED", "AUTH_FAILED",
    "HTTP_STATUS_REJECTED", "INVALID_RESPONSE", "RESPONSE_TOO_LARGE", "DELIVERY_TIMEOUT", "HTTP_DELIVERY_FAILED", "DELIVERY_FAILED",
    "CONTACT_RECIPIENT_NOT_ALLOWED", "CONTACT_CHANNEL_NOT_SET_UP", "SINK_UNAVAILABLE", "DELIVERY_REJECTED", "SLACK_INVALID_BLOCKS",
    "SLACK_MSG_TOO_LONG", "SLACK_MSG_BLOCKS_TOO_LONG", "SLACK_IS_ARCHIVED", "SLACK_UNAVAILABLE", "SLACK_INTERNAL_ERROR",
    "SLACK_FATAL_ERROR", "SLACK_SERVICE_UNAVAILABLE", "SLACK_NO_TEXT", "SLACK_TOO_MANY_ATTACHMENTS", "SLACK_INVALID_ARGUMENTS"]) {
    assert.match(alerts.alertCodeText(code, ko), /[가-힣]/, code);
    assert.doesNotMatch(alerts.alertCodeText(code, en), /[가-힣]|_[A-Z]/, code);
  }
  assert.equal(alerts.alertCodeText("SLACK_INVALID_AUTH", en), "The Slack bot token is not valid.");
  assert.equal(alerts.alertCodeText("SOMETHING_NEW", en), "SOMETHING_NEW");
  // A refused save in words; a refusal with a code of its own keeps the console's wording.
  assert.equal(alerts.alertReason(new DashboardAPIError("ALERTS_CHANNEL_NOT_ALLOWED", 422), en), "Only a channel allowed under Contact delivery can be chosen.");
  assert.equal(alerts.alertReason(new DashboardAPIError("CONTACT_CONSOLE_URL_INVALID", 422), en), "Enter the console address without a path, like https://cremore.example.com.");
  assert.equal(alerts.alertReason(new DashboardAPIError("SETTING_CHANGED_MEANWHILE: another admin saved this setting first; reload it and save again", 409), en),
    "Another admin saved this setting in the meantime. Reload it and save again.");
});

test("only an Incoming Webhook address is sent to be saved", () => {
  const hook = "https://hooks.slack.com/services/T0ABC1234/B0ABC5678/" + "k".repeat(24);
  for (const good of [hook, ` ${hook} `, "https://hooks.slack-gov.com/services/T1/B1/abc_DEF-1"]) assert.equal(alerts.webhookShape(good), true, good);
  for (const bad of ["", "http://hooks.slack.com/services/T1/B1/x", "https://hooks.slack.com.evil.example/services/T1/B1/x",
    `${hook}?x=1`, "https://hooks.slack.com/services/T1/B1", "https://example.com/services/T1/B1/x"]) assert.equal(alerts.webhookShape(bad), false, bad);
  assert.deepEqual(plain(alerts.SEVERITY_CHOICES.map(([id]) => id)), ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
});

test("switching how alerts are sent saves the new way with its webhook or channel, so it works while alerts are on", () => {
  const hook = "https://hooks.slack.com/services/T0ABC1234/B0ABC5678/" + "k".repeat(24);
  const on = view({ transport: "webhook", webhook_saved: true, channel: "#old" });
  assert.deepEqual(plain(alerts.destinationBody(on, "bot", "", "#security-alerts")), { transport: "bot", channel: "#security-alerts" });
  assert.deepEqual(plain(alerts.destinationBody(on, "webhook", ` ${hook} `, "")), { webhook_url: hook });
  assert.deepEqual(plain(alerts.destinationBody(on, "webhook", "", "")), {});  // nothing changed, nothing to save
  const bot = view({ transport: "bot", channel: "#security-alerts" });
  assert.deepEqual(plain(alerts.destinationBody(bot, "webhook", "", "")), { transport: "webhook" });  // the saved URL serves
  assert.deepEqual(plain(alerts.destinationBody(bot, "bot", "", "C0123ABCD9")), { channel: "C0123ABCD9" });
  assert.deepEqual(plain(alerts.destinationBody(bot, "bot", "", "#security-alerts")), {});
});

/** The card as an Admin sees it for one answer of the API, in one language. */
function card(answer, language) {
  const shown = load("@/console/views/settings-alerts.tsx", { overrides: {
    "@/console/data": { ...data, useApi: () => ({ data: answer, error: null, loading: false, reload() {}, replace() {} }), useSaved: () => () => {} },
    "@/console/layer": { useToast: () => () => {} },
  } });
  return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: language }, React.createElement(shown.DetectionAlerts)));
}

test("the card shows each way of sending, in both languages, and never a saved address", () => {
  const webhook = card(view({ console_url: "https://cremore.example.com" }), "ko");
  assert.match(webhook, /<h2>Slack 탐지 알림<\/h2>/);
  assert.match(webhook, /role="switch" class="switch" aria-checked="true" aria-label="Slack 탐지 알림"/);
  assert.match(webhook, /<label for="[^"]+">Incoming Webhook 주소<\/label><input id="[^"]+" type="text" placeholder="저장된 주소 유지 · 바꿀 때만 입력" class="masked"[^>]* value=""\/>/);
  assert.doesNotMatch(webhook, /class="primary-btn"/);  // nothing changed yet: no save button
  assert.match(webhook, /<label for="alerts-severity">보낼 심각도<\/label>/);
  assert.match(webhook, /value="https:\/\/cremore\.example\.com"/);
  assert.match(webhook, /aria-pressed="true">Incoming Webhook<\/button>/);
  assert.doesNotMatch(webhook, /alerts-channel/);
  const bot = card(view({ transport: "bot", bot_ready: true, channel: "C0123ABCD9", channels: ["#security-alerts"] }), "en");
  assert.match(bot, /<label for="alerts-channel">Channel<\/label>/);
  assert.match(bot, /<option value="C0123ABCD9" selected="">C0123ABCD9 \(not allowed any more\)<\/option><option value="#security-alerts">#security-alerts<\/option>/);
  assert.match(bot, /aria-pressed="true">Slack bot<\/button>/);
  assert.doesNotMatch(bot.replace(/>한국어</, "><"), /[가-힣]/);  // each language is named in itself
  const unready = card(view({ enabled: false, transport: "bot", channel: null }), "en");
  assert.match(unready, /Set up the Slack bot under Integrations &gt; Contact delivery first\./);
  assert.match(unready, /aria-checked="false" aria-label="Slack detection alerts" disabled=""/);  // nowhere to send yet
});

test("the card saves to the alerts API, keeps the webhook write-only and sits in Settings", () => {
  const card = source("@/console/views/settings-alerts.tsx");
  assert.equal(alerts.ALERTS_PATH, "settings/detection-alerts");
  assert.match(card, /send<AlertsView>\(ALERTS_PATH, "PUT", change\)/);
  assert.match(card, /send<Tested>\(`\$\{ALERTS_PATH\}\/test`, "POST"\)/);
  // The address field holds only what is typed now: a saved address is never put back into it.
  assert.match(card, /<TextField label=\{L\("Incoming Webhook 주소", "Incoming Webhook URL"\)\} value=\{webhook\} onChange=\{setWebhook\} masked/);
  assert.doesNotMatch(card, /setWebhook\(v\./);
  // Status is read once and then every minute, not on the console's 10-second poll.
  assert.match(card, /useApi<AlertsView>\(ALERTS_PATH, \{ every: 0 \}\)/);
  assert.equal(alerts.STATUS_EVERY, 60_000);
  // Words come in both languages, never one alone.
  assert.ok((card.match(/L\("[^"]*[가-힣][^"]*", "[^"]*"\)/g) || []).length >= 20);
  assert.doesNotMatch(card, />[A-Za-z][a-z]+ [a-z]+[^<{]*</);
  const settings = source("@/console/views/settings.tsx");
  assert.match(settings, /import \{ DetectionAlerts \} from "@\/console\/views\/settings-alerts";/);
  assert.equal((settings.match(/<DetectionAlerts \/>/g) || []).length, 1);
  // In the scan triggers section: the part of Settings about what scans start and what they announce.
  const triggers = settings.slice(settings.indexOf("function ScanTriggers()"), settings.indexOf("function FeedMinutes("));
  assert.match(triggers, /<DetectionAlerts \/>/);
});

test("the card announces the saved event types, not always all three", () => {
  assert.equal(alerts.announced(["finding.created", "finding.reappeared", "finding.location_added"], en),
    "Announces new credential exposures, new locations and reappearances.");
  assert.equal(alerts.announced(["finding.created"], en), "Announces new credential exposures.");
  assert.equal(alerts.announced(["finding.reappeared", "finding.created"], ko), "새 자격증명 노출, 제거 후 다시 노출을 알립니다.");
});

test("a refused test says it was tried without its button too, and promises no resend", () => {
  assert.equal(alerts.testCodeText("DELIVERY_REJECTED", en), "Slack refused the test message's content, also without its button.");
  assert.doesNotMatch(alerts.testCodeText("SLACK_UNAVAILABLE", en), /resumes/);
  assert.equal(alerts.testCodeText("AUTH_FAILED", en), alerts.alertCodeText("AUTH_FAILED", en));
});
