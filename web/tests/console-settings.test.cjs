"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;

test("each queue says what arrives there, the one role its reader needs and why it is not read yet", () => {
  const settings = load("@/console/views/settings.tsx");
  // The address field of each queue is the one the API stores (cremore/scanning/trigger_settings.py QUEUES).
  assert.deepEqual(Object.fromEntries(Object.entries(settings.QUEUES).map(([kind, spec]) => [kind, spec.address])),
    { sqs: "queue_url", pubsub: "subscription", servicebus: "queue" });
  assert.match(settings.QUEUES.pubsub.text[0], /roles\/pubsub\.subscriber/);
  assert.match(settings.QUEUES.servicebus.text[1], /Azure Service Bus Data Receiver/);
  assert.match(settings.QUEUES.sqs.text[1], /ReceiveMessage, DeleteMessage and ChangeMessageVisibility/);
  for (const kind of ["SQS", "PUBSUB", "SERVICEBUS"]) {
    for (const why of ["NOT_ACKNOWLEDGED", "PROFILE_NOT_BOUND"]) assert.doesNotMatch(settings.blockedText(`${kind}_${why}`, L), /_/);
  }
  for (const code of ["SQS_QUEUE_URL_MISSING", "PUBSUB_SUBSCRIPTION_MISSING", "SERVICEBUS_QUEUE_MISSING"]) assert.doesNotMatch(settings.blockedText(code, L), /_/);
  assert.equal(settings.blockedText(null, L), null);
  // The providers a change feed paces (CHANGE_FEED_PROVIDERS), Notion included.
  assert.deepEqual([...settings.FEED_PROVIDERS], ["github", "gitlab", "azure_devops", "bitbucket", "confluence", "notion"]);
  for (const level of ["low", "medium", "high"]) assert.ok(settings.CONFIDENCE[level], level);
});

test("the full-scan start is chosen on the display zone's clock and saved as the UTC minute", () => {
  const settings = load("@/console/views/settings.tsx");
  const kst = settings.startChoices(1020, "Asia/Seoul");
  // 02:00 KST is 17:00 UTC (the default); every hour of the day is offered once, in the order the clock reads.
  assert.equal(kst.length, 24);
  assert.deepEqual([...kst.slice(0, 3)].map(choice => [choice.id, choice.label]), [["900", "00:00"], ["960", "01:00"], ["1020", "02:00"]]);
  assert.equal(kst.find(choice => choice.label === "14:00").id, "300");
  const utc = settings.startChoices(1020, "UTC");
  assert.equal(utc.find(choice => choice.id === "1020").label, "17:00");
  // A saved minute that is not on an hour of the shown clock stays choosable as it is.
  const odd = settings.startChoices(1050, "Asia/Seoul");
  assert.equal(odd.length, 25);
  assert.equal(odd.find(choice => choice.id === "1050").label, "02:30");
  // The device's own zone at a given moment: here an offset of -5 hours.
  const device = settings.startChoices(1020, "LOCAL", { getTimezoneOffset: () => 300 });
  assert.equal(device.find(choice => choice.id === "1020").label, "12:00");
});

/** The schedules card for one answer of settings/scan-triggers, in one language. */
function triggersCard(answer, language) {
  const data = load("@/console/data.ts");
  const layer = load("@/console/layer.tsx");
  const locale = load("@/components/locale.tsx");
  const shown = load("@/console/views/settings.tsx", { extraExports: "\nexport { ScanTriggers };", overrides: {
    "@/console/data": { ...data, useSaved: () => () => {},
      useApi: path => ({ data: path === "settings/scan-triggers" ? answer : [], error: null, loading: false, reload() {}, replace() {} }) },
    "@/console/layer": { ...layer, useToast: () => () => {} },
  } });
  return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: language }, React.createElement(shown.ScanTriggers)));
}

const queue = { enabled: false, switch: false, installation_allows: true, profile_id: "", profile_id_locked: false,
  dedicated_acknowledged: false, dedicated_acknowledged_locked: false, blocked_by: null };
const triggers = (schedules = {}, feeds = {}) => ({ updated_by: null, updated_at: null, sqs: queue, pubsub: queue, servicebus: queue,
  schedules: { enabled: true, switch: true, installation_allows: true, full_scan_default_minutes: 720, full_scan_start_minute: 1020, ...schedules },
  change_feeds: { enabled: true, switch: true, installation_allows: true, ...feeds,
    minutes: { github: 5, gitlab: 5, azure_devops: 5, bitbucket: 15, confluence: 5, notion: 5 } } });

test("the schedules card offers the default cadence, its start on the display clock, every feed's minutes and how scans overlap", () => {
  const html = triggersCard(triggers(), "ko");
  assert.match(html, /<label for="full-scan-default">전체 검사 기본 주기<\/label>/);
  assert.match(html, /<option value="720" selected="">하루 2회<\/option>/);
  for (const runs of ["하루 1회", "하루 3회", "하루 24회", "끄기"]) assert.match(html, new RegExp(`>${runs}</option>`), runs);
  assert.match(html, /<label for="full-scan-start">시작 시각 \(KST\)<\/label>/);
  assert.match(html, /<option value="1020" selected="">02:00<\/option>/);
  // Full scans start at a fixed time per scope within 4 hours of the start time, not all at once.
  assert.match(html, /범위마다 정해진 시각에, 시작 시각부터 최대 4시간 뒤\(주기가 8시간보다 짧으면 주기의 절반\) 사이에 시작하며 이 시각은 매번 같습니다/);
  for (const provider of ["github", "gitlab", "azure_devops", "confluence", "notion"]) {
    assert.match(html, new RegExp(`id="feed-${provider}"[^>]*value="5"`), provider);
  }
  assert.match(html, /id="feed-bitbucket"[^>]*value="15"/);
  assert.match(html, /서로 다른 연결의 검사는 worker 동시 실행 수만큼 함께 진행합니다/);
  // Switched off by an Admin, a default-on switch says who turned it off, and its settings fold away.
  const off = triggersCard(triggers({ enabled: false, switch: false }, { enabled: false, switch: false }), "en");
  assert.equal((off.match(/An Admin switched it off\. Nothing runs until it is switched on\./g) || []).length, 2);
  assert.doesNotMatch(off, /full-scan-default|feed-notion/);
});

test("the schedule settings save the cadence, the start minute and the feed minutes to the API, admin-only", () => {
  const screen = source("@/console/views/settings.tsx");
  assert.match(screen, /put\(\{ full_scan_default_minutes: Number\(event\.target\.value\) \}\)/);
  assert.match(screen, /put\(\{ full_scan_start_minute: Number\(event\.target\.value\) \}\)/);
  assert.match(screen, /put\(\{ change_feed_minutes: \{ \.\.\.t\.change_feeds\.minutes, \[provider\]: minutes \} \}\)/);
  // What runs at the same time, said as it is: other connections at once, an event run beside a sweep, no root twice.
  assert.match(screen, /worker 동시 실행 수만큼 함께 진행합니다/);
  assert.match(screen, /never read twice at once/);
  assert.doesNotMatch(screen, /Legacy schedules retain daily reconciliation/);
});

test("a typed number is saved only in range, kept (marked) out of it, and a locked switch still turns off", () => {
  const settings = load("@/console/views/settings.tsx");
  assert.equal(settings.typedNumber(null, 5, 1, 1440), "keep");
  assert.equal(settings.typedNumber("5", 5, 1, 1440), "keep");
  assert.equal(settings.typedNumber(" 15 ", 5, 1, 1440), "save");
  for (const typed of ["0", "1441", "85.5", "", "abc", "-3"]) assert.equal(settings.typedNumber(typed, 5, 1, 1440), "invalid", typed);
  assert.equal(settings.switchLocked(false, false), true);
  assert.equal(settings.switchLocked(false, true), false);  // on while locked: it can still be turned off
  assert.equal(settings.switchLocked(true, false), false);
});

test("what the installation holds reads in Korean, and a payload it could not have produced is refused", () => {
  const settings = load("@/console/views/settings.tsx");
  const view = { sealing: { root: "FINGERPRINT_KEY", held_here: true, key_id: "k1", openers: 1, unreachable: null },
    items: [{ name: "sealing master", where: "FINGERPRINT_KEY", held_here: true, rotatable: false, reason: "no sealing source set" },
      { name: "SEALING_KEY_PREVIOUS", where: "ENVIRONMENT", held_here: true, rotatable: true, reason: "configured opening material" },
      { name: "SECRET_STORE_TOKEN", where: "ENVIRONMENT", held_here: true, rotatable: true, reason: "a static store token" },
      { name: "API_TOKEN", where: "ENVIRONMENT", held_here: true, rotatable: false, reason: "the shared token" }],
    reasons: ["SEALING_KEY_PREVIOUS_HELD_HERE", "SECRET_STORE_TOKEN_HELD_HERE", "SEALING_MASTER_CANNOT_ROTATE"] };
  const projected = settings.projectLocalCredentials(view);
  assert.equal(settings.keptLocally(projected), 4);
  for (const one of projected.items) {
    assert.match(settings.itemWhy(one, "FINGERPRINT_KEY", "ko"), /[가-힣]/, one.name);
    assert.equal(settings.itemWhy(one, "FINGERPRINT_KEY", "en"), one.reason);
  }
  for (const code of view.reasons) assert.notEqual(settings.localCredentialReason(code, "ko"), code, code);
  assert.equal(settings.rootLabel("KMS", "ko"), "AWS KMS");
  for (const bad of [null, [], { sealing: {}, items: [], reasons: [] }, { ...view, items: [{ name: 1 }] }, { ...view, reasons: [1] }]) {
    assert.equal(settings.projectLocalCredentials(bad), null);
  }
});

test("the settings screen is the console's, and every control saves to the API that owns it", () => {
  assert.match(source("@/console/app.tsx"), /settings: Settings,/);
  const screen = source("@/console/views/settings.tsx");
  for (const path of ["settings/sign-in", "settings/credential-verification", "settings/capability-probe", "settings/cross-host-verification",
    "settings/scan-triggers", "settings/scan-triggers/bindable-profiles", "settings/learned-false-positives", "rules/learned-fp",
    "settings/local-credentials"]) assert.ok(screen.includes(`"${path}"`), path);
  // ?section= opens a part; the integrations page links to section=login.
  assert.match(screen, /const SECTIONS: Section\[\] = \["login", "verification", "triggers", "triage", "local"\];/);
  assert.match(screen, /send\(`rules\/learned-fp\/\$\{encodeURIComponent\(profile\.id\)\}\/\$\{action\}`, "POST"\)/);
  // The display timezone is this device's own preference, never a setting of the installation.
  assert.match(screen, /onChange=\{setDisplayTimezone\}/);
});

test("Google sign-in says where its roles come from and what stops the role groups from being read", () => {
  const settings = load("@/console/views/settings.tsx");
  assert.equal(settings.roleGroupProblem(null, L), null);
  for (const code of ["GOOGLE_WORKSPACE_PEOPLE_DIRECTORY_REQUIRED", "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED", "GOOGLE_WORKSPACE_HTTP_404",
    "SECRET_UNAVAILABLE"]) assert.ok(!settings.roleGroupProblem(code, L).includes(code), code);
  assert.match(settings.roleGroupProblem("GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED", L), /admin\.directory\.group\.member\.readonly/);
  assert.match(settings.roleGroupProblem("SOMETHING_ELSE", L), /SOMETHING_ELSE.*다시 읽습니다/);
  const screen = source("@/console/views/settings.tsx");
  assert.match(screen, /members=\{workspace \? workspace\.groups\[role\]\?\.members \?\? null : undefined\}/);
  assert.match(screen, /\{problem \? <Banner tone="warn" icon="alert">\{problem\}<\/Banner> : null\}/);
});