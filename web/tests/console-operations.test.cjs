"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

const item = (fields) => ({ key: "k", name: "n", provider: "github", kind: "CONTENT", auth_state: "READY", auth_renewal: "MANUAL",
  expires_source: null, freshness: "FRESH", last_status: "COMPLETE", ...fields });

test("a connection needs a look for its sign-in, expiry, stale data or failure, never while stopped", () => {
  const ops = load("@/console/views/operations.tsx");
  assert.equal(ops.needsAttention(item({})), false);
  for (const auth_state of ["EXPIRING", "REAUTH_REQUIRED", "PERMISSION_LIMITED", "SECRET_UNAVAILABLE"]) assert.equal(ops.needsAttention(item({ auth_state })), true, auth_state);
  assert.equal(ops.needsAttention(item({ freshness: "STALE" })), true);
  assert.equal(ops.needsAttention(item({ last_status: "FAILED" })), true);
  assert.equal(ops.needsAttention(item({ auth_state: "DISABLED", last_status: "FAILED", freshness: "STALE" })), false);
  // Every state, renewal and reason the health list reports reads in words (cremore/operations/health.py).
  for (const code of ["READY", "EXPIRING", "REAUTH_REQUIRED", "PERMISSION_LIMITED", "SECRET_UNAVAILABLE", "DISABLED", "UNKNOWN", "FRESH",
    "STALE", "NEVER_COLLECTED", "NOT_SCHEDULED", "COMPLETE", "PARTIAL", "FAILED", "NOT_COLLECTED"]) assert.ok(ops.HEALTH[code], code);
  for (const renewal of ["AUTO", "MANUAL", "HUMAN_SESSION", "EXTERNAL", "UNKNOWN"]) assert.ok(ops.RENEWAL[renewal], renewal);
  for (const code of ["AUTH_EXPIRING", "AUTH_EXPIRED", "AUTH_LIFETIME_TOO_SHORT", "AUTH_FRESHNESS_UNKNOWN", "NO_CREDENTIALS", "NO_CREDENTIAL",
    "CREDENTIAL_REJECTED", "SECRET_UNAVAILABLE", "METADATA_SECRET_UNAVAILABLE", "AWS_LOGIN_REQUIRED", "AWS_SCANNER_IDENTITY_CHANGED",
    "GCP_OAUTH_SETUP_REQUIRED", "GCP_OAUTH_SCOPE_REQUIRED", "GCP_OAUTH_OFFLINE_ACCESS_REQUIRED", "GCP_AMBIENT_CREDENTIALS_REQUIRED",
    "AZURE_KEY_VAULT_AMBIENT_CREDENTIALS_REQUIRED", "SCAN_FAILED", "COLLECTION_FAILED", "ACCOUNT_NOT_VALIDATED"]) {
    for (const locale of ["ko", "en"]) {
      const text = ops.healthReason(code, locale);
      assert.ok(text && text !== code && !text.includes(code.replaceAll("_", " ")) && !/^[A-Z ]+$/.test(text), `${code} ${locale}: ${text}`);
    }
  }
});

test("only a credential that does not renew itself and has no provider date takes an Admin's expiry", () => {
  const ops = load("@/console/views/operations.tsx");
  assert.equal(ops.acceptsOperatorExpiry(item({})), true);
  assert.equal(ops.acceptsOperatorExpiry(item({ expires_source: "OPERATOR" })), true);
  assert.equal(ops.acceptsOperatorExpiry(item({ auth_renewal: "AUTO" })), false);
  assert.equal(ops.acceptsOperatorExpiry(item({ expires_source: "PROVIDER" })), false);
  assert.equal(ops.acceptsOperatorExpiry(item({ auth_state: "DISABLED" })), false);
  const L = (ko, en) => en;
  assert.deepEqual([45, 600, 7200, 259_200].map((seconds) => ops.duration(seconds, L)), ["45s", "10 min", "2 h", "3 days"]);
});

test("a team install leaning on one person's sign-in is said at the top, from the server's own alert", () => {
  const ops = load("@/console/views/operations.tsx");
  const alert = code => ({ worker: null, alerts: [{ code, resource_type: "aws_identity", resource_id: "worker" }] });
  assert.equal(ops.humanSessionOnTeamInstall(alert("HUMAN_SESSION_IN_SERVER_DEPLOYMENT")), true);
  assert.equal(ops.humanSessionOnTeamInstall(alert("WORKER_HEARTBEAT_MISSING")), false);
  assert.equal(ops.humanSessionOnTeamInstall({ worker: null }), false);
  assert.equal(ops.humanSessionOnTeamInstall(undefined), false);
  // The screen shows it first, under the page head.
  assert.match(source("@/console/views/operations.tsx"), /<PageHead title=\{title\} meta=\{meta\} \/>\s*\{humanSessionOnTeamInstall\(status\.data\) \? <Banner tone="warn"/);
});

test("a change feed failing for over an hour reads whose it is, why, since when and what it means", () => {
  const ops = load("@/console/views/operations.tsx");
  const alert = (code, fields = {}) => ({ code, resource_type: "connection", resource_id: "c1", provider: "github", failing_roots: 2,
    failing_since: "2026-10-01T03:00:00+00:00", error_codes: ["SOURCE_RATE_LIMITED"], ...fields });
  const job = { code: "JOB_FAILED", resource_type: "job", resource_id: "j1" };
  assert.deepEqual([...ops.feedAlerts({ worker: null, alerts: [job, alert("CHANGE_FEED_RATE_LIMITED")] }).map(row => row.code)], ["CHANGE_FEED_RATE_LIMITED"]);
  assert.equal(ops.feedAlerts(undefined).length, 0);
  const now = Date.parse("2026-10-02T00:00:00Z");  // dates read in the default display zone, KST
  const scheduled = item({ id: "c1", name: "app" }), unscheduled = item({ id: "c1", name: "app", freshness: "NOT_SCHEDULED" });
  assert.equal(ops.feedAlertText(alert("CHANGE_FEED_RATE_LIMITED"), scheduled, "ko", now),
    "GitHub 연결 ‘app’의 변경 감지가 10월 1일 12:00부터 실패하고 있습니다(요청 제한). 실패하는 대상 2곳의 변경 검사는 조회가 성공할 때까지 멈춰 있고, 예약 검사(기본 매일 전체 검사)는 계속 돕니다.");
  assert.equal(ops.feedAlertText(alert("CHANGE_FEED_UNAVAILABLE", { failing_roots: 1 }), scheduled, "en", now),
    "The change feed of GitHub connection ‘app’ has failed since Oct 1 12:00 (provider outage). Change scans of the 1 failing target wait until a look succeeds; scheduled scans (a full scan daily by default) still run.");
  for (const [code, ko, en] of [["CHANGE_FEED_RATE_LIMITED", "요청 제한", "rate limited"], ["CHANGE_FEED_UNAVAILABLE", "공급자 장애", "provider outage"],
    ["CHANGE_FEED_FAILING", "조회 실패", "lookups failing"]]) {
    assert.ok(ops.feedAlertText(alert(code), scheduled, "ko", now).includes(`(${ko}). 실패하는 대상 2곳의`), code);
    assert.ok(ops.feedAlertText(alert(code), scheduled, "en", now).includes(`(${en}). Change scans of the 2 failing targets`), code);
  }
  // Only the failing targets wait: the text never says the whole connection's change scans stopped.
  for (const locale of ["ko", "en"]) for (const row of [scheduled, unscheduled, undefined]) {
    assert.doesNotMatch(ops.feedAlertText(alert("CHANGE_FEED_FAILING"), row, locale, now), /이 연결의 변경 검사|for this connection/);
  }
  // With no scan scheduled nothing reads those targets' changes: the text does not promise a full scan.
  assert.match(ops.feedAlertText(alert("CHANGE_FEED_FAILING"), unscheduled, "ko", now), /멈춰 있고, 예약 검사도 없어 직접 검사하기 전까지 그 대상의 바뀐 내용을 읽지 않습니다\.$/);
  assert.match(ops.feedAlertText(alert("CHANGE_FEED_FAILING"), unscheduled, "en", now), /wait until a look succeeds, and no scan is scheduled, so nothing reads their changes until someone scans\.$/);
  // Before the health list arrives the service still names the connection, and nothing is said of schedules.
  assert.equal(ops.feedAlertText(alert("CHANGE_FEED_FAILING"), undefined, "en", now),
    "The change feed of a GitHub connection has failed since Oct 1 12:00 (lookups failing). Change scans of the 2 failing targets wait until a look succeeds.");
  assert.equal(ops.feedAlertText(alert("CHANGE_FEED_FAILING"), undefined, "ko", now),
    "GitHub 연결의 변경 감지가 10월 1일 12:00부터 실패하고 있습니다(조회 실패). 실패하는 대상 2곳의 변경 검사는 조회가 성공할 때까지 멈춰 있습니다.");
});

test("the response threads' job reads as stopped (where it runs) or as replies waiting (why, and what to check)", () => {
  const ops = load("@/console/views/operations.tsx");
  const now = Date.parse("2026-10-02T00:00:00Z");
  const base = { resource_type: "response_threads", resource_id: "progress", failing_since: "2026-10-01T03:00:00+00:00" };
  const stopped = { code: "RESPONSE_THREADS_STOPPED", ...base, last_run_at: null, open_threads: 2 };
  const failing = { code: "RESPONSE_THREADS_FAILING", ...base, last_run_at: "2026-10-01T23:59:00+00:00", owed_replies: 1, error_codes: ["SLACK_RATE_LIMITED"] };
  const job = { code: "JOB_FAILED", resource_type: "job", resource_id: "j1" };
  assert.deepEqual([...ops.threadAlerts({ worker: null, alerts: [job, stopped, failing] }).map(row => row.code)],
    ["RESPONSE_THREADS_STOPPED", "RESPONSE_THREADS_FAILING"]);
  assert.equal(ops.threadAlerts(undefined).length, 0);
  assert.equal(ops.threadAlertText(stopped, "ko", now),
    "대응 요청의 팀 채널 스레드에 진행 상황을 올리는 작업이 10월 1일 12:00부터 돌지 않았습니다(열린 스레드 2개). 혼합 worker나 역할을 나눈 설치의 control 프로세스가 이 작업을 1분마다 실행하니, 그 프로세스가 도는지 확인하세요.");
  assert.equal(ops.threadAlertText(failing, "en", now),
    "1 progress reply has waited since Oct 1 12:00 to go to response requests' team channel threads. Last error: Slack's rate limit was reached. Send again shortly. Check the Slack bot token and its scopes (chat:write, channels:read, groups:read) under Integrations > Other settings > Contact delivery. Once fixed, what waited goes out in order.");
  // An unknown code still reads as a sentence; no code, no "last error".
  assert.match(ops.threadAlertText({ ...failing, error_codes: ["SLACK_SOMETHING_NEW"] }, "ko", now), /마지막 오류: SLACK_SOMETHING_NEW\. 연동 서비스/);
  assert.doesNotMatch(ops.threadAlertText({ ...failing, error_codes: [] }, "ko", now), /마지막 오류/);
  // A missing scope may be chat:write: the banner never promises that DMs still go out.
  for (const locale of ["ko", "en"]) {
    const text = ops.threadAlertText({ ...failing, error_codes: ["SLACK_SCOPE_MISSING"] }, locale, now);
    assert.match(text, locale === "ko" ? /마지막 오류: Slack 봇에 필요한 권한이 없습니다\. / : /Last error: The Slack bot lacks a scope it needs\. /);
    assert.doesNotMatch(text, /DM/);
  }
});

test("an entered expiry is a real day from today to ten years ahead, never something that clears it", () => {
  const ops = load("@/console/views/operations.tsx");
  assert.equal(ops.latestExpiryDay("2026-09-30"), "2036-09-30");
  assert.equal(ops.expiryValid("2026-09-30", "2026-09-30"), true);
  assert.equal(ops.expiryValid("2036-09-30", "2026-09-30"), true);
  for (const day of ["", "2026-09-29", "2036-10-01", "20266-01-01", "2027-02-30", "2027-02-30x", "2027-13-01", "not a day"]) assert.equal(ops.expiryValid(day, "2026-09-30"), false, day);
  assert.equal(ops.expiryValid("2028-02-29", "2026-09-30"), true);
  const screen = source("@/console/views/operations.tsx");
  assert.match(screen, /disabled=\{busy \|\| !expiryValid\(day, today\)\} onClick=\{\(\) => \{ const at = expiryAt\(day\); if \(at\) void save\(at\); \}\}/);
  assert.match(screen, /\{L\(`만료 \$\{fmtDay\(item\.expires_at, locale\)\}`/);
});

test("a test event is followed at every destination the exporter reported until each delivered or held it", () => {
  const ops = load("@/console/views/operations.tsx");
  const done = { destination: "splunk", attempts: 1, delivered_at: "2026-09-30T01:00:00Z", held_at: null, error_code: null };
  const held = { destination: "webhook", attempts: 3, delivered_at: null, held_at: "2026-09-30T01:01:00Z", error_code: "HTTP_5XX" };
  // A destination that has not tried it yet is waiting, not missing: one delivery is not the whole answer.
  let outcome = ops.testOutcome([done], ["splunk", "webhook"]);
  assert.equal(outcome.settled, false);
  assert.deepEqual([...outcome.rows.map((row) => row.destination)], ["splunk", "webhook"]);
  outcome = ops.testOutcome([done, held], ["splunk", "webhook"]);
  assert.deepEqual([outcome.settled, outcome.held, outcome.delivered], [true, true, false]);
  outcome = ops.testOutcome([done], ["splunk"]);
  assert.deepEqual([outcome.settled, outcome.delivered], [true, true]);
  assert.equal(ops.testOutcome([], []).settled, false);
});

test("the operations screen is the console's and follows a test event only so long", () => {
  assert.match(source("@/console/app.tsx"), /operations: Operations,/);
  const screen = source("@/console/views/operations.tsx");
  for (const path of ["HEALTH_PATH", '"siem/status"', '"operations/status"']) assert.match(screen, new RegExp(`useApi<[^>]+>\\(${path}, \\{ every: 15_000 \\}\\)`));
  assert.match(screen, /const ready = \[health, siem, status\]\.every\(read => Boolean\(read\.data \|\| read\.error\)\);/);
  assert.match(screen, /if \(section === "siem" && ready\) document\.getElementById\("ops-siem"\)/);
  assert.match(screen, /if \(!test \|\| test\.tries >= 20 \|\| testOutcome\(test\.deliveries, names\)\.settled\) return;/);
  assert.match(screen, /send\(`siem\/destinations\/\$\{encodeURIComponent\(destination\)\}\/release-held`, "POST"\)/);
  assert.match(screen, /send\(`operations\/connections\/\$\{encodeURIComponent\(item\.key\)\}\/expiry`, "PUT", \{ expires_at: value \}\)/);
});
