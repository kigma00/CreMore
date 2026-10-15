"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;
const record = (fields) => ({ provider: "aws", credential_id: "11111111-1111-4111-8111-111111111111", hint: "AKIA••••••••DEMO", ...fields });
const event = (fields) => ({ event_id: "", event_time: "2026-09-30T01:00:00Z", region: "ap-northeast-2", evidence_source: "EVENT_HISTORY",
  event_category: "MANAGEMENT", event_source: "s3.amazonaws.com", event_name: "GetObject", access_mode: "READ", outcome: "SUCCEEDED", resources: [], ...fields });
// A snapshot as GET /api/v1/credentials/{id}/usage serves it: classify_events puts the counts under techniques.
const snapshot = (fields) => ({ credential_class: "LONG_LIVED", collection_status: "COMPLETE", region_discovery_status: "COMPLETE", event_scope: "MANAGEMENT",
  window_start: "2026-07-02T00:00:00Z", window_end: "2026-09-30T00:00:00Z", collected_at: "2026-09-30T00:00:00Z",
  regions_discovered: 17, regions_complete: 17, regions_failed: 0, regions_capped: 0, events: [], coverage: [], scenarios: [],
  techniques: { revision: "r1", observed: [], classified_events: 0, total_events: 0 }, ...fields });

function html(element, value = "ko") {
  const locale = load("@/components/locale.tsx");
  return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value }, element));
}

test("a lookup is offered where the service answers about one credential now: a discovered AWS access key", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  assert.equal(usage.usageLookup(record({})), true);
  assert.equal(usage.usageLookup(record({ hint: "ASIA••••••••DEMO" })), true);
  assert.equal(usage.usageLookup(record({ hint: "ghp_••••" })), false);
  assert.equal(usage.usageLookup(record({ provider: "gcp" })), false);
  assert.equal(usage.usageLookup(record({ credential_id: null })), false);  // an issued key never found exposed
  assert.equal(usage.usageLookup(record({ hint: null })), false);
  // A session key is looked up in the account its verified principal names; a long-lived key needs none.
  assert.equal(usage.needsPrincipal(record({ hint: "ASIA••••••••DEMO" }), null), true);
  assert.equal(usage.needsPrincipal(record({ hint: "ASIA••••••••DEMO" }), "arn:aws:iam::123456789012:role/app"), false);
  assert.equal(usage.needsPrincipal(record({}), null), false);
});

test("the calls read by service, busiest first, with writes, denials and the latest time", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  const rows = [...usage.byService([
    event({}), event({ event_time: "2026-09-30T03:00:00Z", access_mode: "WRITE", event_name: "PutObject" }),
    event({ event_source: "iam.amazonaws.com", event_name: "CreateUser", access_mode: "WRITE", outcome: "DENIED", event_time: null }),
  ])].map(row => ({ ...row }));
  assert.deepEqual(rows, [
    { service: "s3", calls: 2, writes: 1, denied: 0, last: "2026-09-30T03:00:00Z" },
    { service: "iam", calls: 1, writes: 1, denied: 1, last: null },
  ]);
});

test("a lookup's status says what it covers and why it stopped short; only someone who can look it up is told to", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  assert.match(usage.usageStatusText(snapshot({ collection_status: "NOT_COLLECTED" }), L, true), /백그라운드/);
  assert.equal(usage.usageStatusText(snapshot({ collection_status: "NOT_COLLECTED" }), L, false), "아직 조회하지 않았습니다.");
  assert.match(usage.usageStatusText(snapshot({ collection_status: "ACCOUNT_UNVERIFIED" }), L, true), /다시 조회하면/);
  assert.doesNotMatch(usage.usageStatusText(snapshot({ collection_status: "ACCOUNT_UNVERIFIED" }), L, false), /다시 조회/);
  assert.equal(usage.usageStatusText(snapshot({ collection_status: "PARTIAL", regions_complete: 15, regions_failed: 2 }), L, true),
    "리전 17곳 중 15곳을 다 읽었습니다 · 2곳은 읽지 못했습니다.");
  assert.match(usage.usageStatusText(snapshot({ collection_status: "PARTIAL", region_discovery_status: "FALLBACK", regions_discovered: 10, regions_complete: 10 }), L, true),
    /켜 둔 리전 목록을 읽지 못해 기본 리전을 읽었습니다/);
  assert.match(usage.usageStatusText(snapshot({ collection_status: "PARTIAL", region_discovery_status: "CAPPED", regions_discovered: 25, regions_complete: 25 }), L, true),
    /25곳까지만 읽었습니다/);
  assert.match(usage.usageStatusText(snapshot({ collection_status: "PARTIAL", regions_capped: 1 }), L, true), /호출 100건까지만/);
  const capped = snapshot({ collection_status: "PARTIAL", regions_capped: 1, events_per_region: 1000 });
  assert.match(usage.usageStatusText(capped, L, true), /호출 1000건까지만/);
  assert.match(usage.usageStatusText(capped, (_ko, en) => en, true), /first 1000 calls/);
  for (const code of ["PAGE_LIMIT_REACHED", "BYTE_LIMIT_REACHED"]) {
    const reason = usage.usageStatusText({ ...capped, coverage: [{ status: "CAPPED", error_code: code }] }, L, true);
    assert.match(reason, /페이지 또는 저장 크기 한도/);
    assert.doesNotMatch(reason, /호출 1000건/);
  }
  const failed = snapshot({ collection_status: "FAILED", region_discovery_error: "AccessDenied",
    coverage: [{ region: "ap-northeast-2", status: "FAILED", error_code: "AccessDenied" }, { region: "us-east-1", status: "FAILED", error_code: "ThrottlingException" }] });
  assert.deepEqual([...usage.failureCodes(failed)], ["AccessDenied", "ThrottlingException"]);
  assert.equal(usage.usageStatusText(failed, L, true), "조회하지 못했습니다 (AccessDenied, ThrottlingException). 다시 조회해 보세요.");
  assert.equal(usage.usageStatusText(failed, L, false), "조회하지 못했습니다 (AccessDenied, ThrottlingException).");
  assert.equal(usage.usageStatusText(snapshot({}), L, true), null);
});

test("what a lookup saw renders from the API's snapshot, and a lookup that did not finish never reads as no calls", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  const none = "조회 기간의 관리 이벤트에 이 키로 한 호출이 없습니다.";
  // Finished with nothing seen: that is what it says.
  assert.ok(html(React.createElement(usage.UsageBody, { u: snapshot({}), canLookup: true })).includes(none));
  // Did not finish: no "no calls", and no count.
  const failed = html(React.createElement(usage.UsageBody, { u: snapshot({ collection_status: "FAILED", regions_complete: 0 }), canLookup: true }));
  assert.ok(!failed.includes(none));
  assert.match(failed, /관측된 호출<\/dt><dd>—<\/dd>/);
  const partial = html(React.createElement(usage.UsageBody, { u: snapshot({ collection_status: "PARTIAL", regions_complete: 16, regions_failed: 1 }), canLookup: true }));
  assert.ok(!partial.includes(none));
  // The calls: by service, what they do (techniques.observed) and the latest ones, newest first as served.
  const seen = snapshot({ events: [event({ event_name: "CreateAccessKey", event_source: "iam.amazonaws.com", access_mode: "WRITE", outcome: "DENIED", technique_id: "T1098.001" }),
    event({ event_name: "ListBuckets", technique_id: "T1619" }), event({})],
  techniques: { revision: "r1", observed: [{ technique_id: "T1098.001", technique_name: "Account Manipulation: Additional Cloud Credentials", events: 1 },
    { technique_id: "T1619", technique_name: "Cloud Storage Object Discovery", events: 1 }], classified_events: 2, total_events: 3 } });
  const markup = html(React.createElement(usage.UsageBody, { u: seen, canLookup: false }));
  assert.match(markup, /관측된 호출<\/dt><dd>3건 · 거부 1건<\/dd>/);
  assert.match(markup, /호출이 하는 일/);
  assert.match(markup, /Account Manipulation: Additional Cloud Credentials · 1건/);
  assert.match(markup, /최근 호출 · 3건 중 3건/);
  assert.ok(markup.indexOf("CreateAccessKey") < markup.indexOf("ListBuckets"));
  assert.match(markup, /s3 · 2건 · 마지막/);
});

test("the usage card sits under the key facts with the verified principal, and an Analyst can run the lookup", () => {
  const tabs = source("@/console/views/credentials/tabs.tsx");
  // The principal is null once the detail says there is none, undefined while it loads.
  assert.match(tabs, /title=\{L\("핵심 정보", "Key facts"\)\}>[\s\S]*?<\/Card>\s*<UsageCard c=\{c\} canLookup=\{canLookup\} principal=\{detail \? detail\.credential\.principal \?\? null : undefined\} \/>/);
  assert.match(source("@/console/views/credentials/drawer.tsx"), /<OverviewTab [^>]*canLookup=\{hasRole\(session\.role, "Analyst"\)\}/);
  // The lookup and the view are the API's own routes; a refusal reads in words.
  const card = source("@/console/views/credentials/usage.tsx");
  assert.match(card, /`credentials\/\$\{c\.credential_id\}\/usage`/);
  assert.match(card, /`credentials\/\$\{c\.credential_id\}\/usage\/refresh\?background=true`, "POST"/);
  const data = load("@/console/data.ts");
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  assert.match(data.reasonText(new DashboardAPIError("USAGE_LOOKUP_OFF: observed-use lookup is switched off", 501), L), /'발견한 Credential 조사 기능'에서 켭니다/);
  assert.match(data.reasonText(new DashboardAPIError("ACCOUNT_OWNER_UNKNOWN: no connected account reports this access key.", 409), L), /이 키를 보고한 계정이 없습니다/);
  // Every reason an account session can be refused for reads in words, in both languages and for either purpose:
  // aws_sessions.refusal/_vend/_assume, aws_access.use_refusal and org_blocks (AWS Organizations account states), and
  // the role checks effective_validation hands on (investigation/role_validation.py).
  const EN = (_ko, en) => en;
  for (const code of ["ACCOUNT_OWNER_UNKNOWN", "ACCOUNT_NOT_CONNECTED", "IDENTITY_NOT_APPROVED", "AWS_LOGIN_REQUIRED", "AWS_IDENTITY_UNAVAILABLE",
    "AWS_IDENTITY_CHANGED", "ACCOUNT_MISMATCH", "ACCESS_NOT_CONFIGURED", "AWS_SSO_SESSION_UNKNOWN", "AWS_SSO_SESSION_CHANGED",
    "IDENTITY_CENTER_REGION_REQUIRED", "SSO_CACHE_NOT_WRITABLE", "SSO_ROLE_NOT_ASSIGNED", "ASSUME_ROLE_DENIED", "ACCOUNT_DISABLED",
    "ORG_ACCOUNT_REMOVED", "SSO_ASSIGNMENT_REMOVED", "ORG_STATE_UNKNOWN", "ORG_ACCOUNT_SUSPENDED", "ORG_ACCOUNT_PENDING_CLOSURE",
    "ORG_ACCOUNT_CLOSED", "ORG_ACCOUNT_PENDING_ACTIVATION", "OUT_OF_DEPLOYMENT_SCOPE", "REVALIDATION_REQUIRED", "ACCOUNT_NOT_VALIDATED",
    "NO_ROLE_RECORDED", "NO_EXTERNAL_ID", "NO_PERMISSION_SET_RECORDED", "CALLER_IDENTITY_FAILED", "PERMISSION_SET_MISMATCH",
    "WORKER_AWS_NOT_CONFIGURED"]) {
    for (const purpose of ["scanner", "remediation"]) {
      const error = new DashboardAPIError(`${code}: AWS ${purpose} access to account 123456789012 is not available`, 409);
      assert.doesNotMatch(data.reasonText(error, L), /access to account|쓸 수 없습니다 \(/, `${code} ko`);
      assert.doesNotMatch(data.reasonText(error, EN), /access to account|cannot use this AWS account now/, `${code} en`);
    }
  }
  // A role or access reason names no one purpose: the same codes come back from key actions.
  for (const code of ["ASSUME_ROLE_DENIED", "NO_ROLE_RECORDED", "ACCESS_NOT_CONFIGURED", "ACCOUNT_MISMATCH"]) {
    const error = new DashboardAPIError(`${code}: AWS remediation access to account 123456789012 is not available`, 409);
    assert.doesNotMatch(data.reasonText(error, L), /읽기 역할|CreMore의 AWS 신원이 이 계정/, code);
    assert.doesNotMatch(data.reasonText(error, EN), /read role|No permission set is chosen|CreMore's AWS identity does not belong/, code);
  }
  assert.equal(data.reasonText(new DashboardAPIError("ORG_ACCOUNT_SOMETHING_NEW: AWS scanner access to account 123456789012 is not available", 409), L),
    "CreMore가 지금 이 AWS 계정을 쓸 수 없습니다 (ORG_ACCOUNT_SOMETHING_NEW).");
});

test("a session key waits for its principal; an unconfirmed record without calls has no count; only a failure toasts as one", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  const card = (fields, props) => html(React.createElement(usage.UsageCard, { c: record(fields), canLookup: true, ...props }));
  const waiting = card({ hint: "ASIA••••••••DEMO" }, { principal: null });
  assert.match(waiting, /세션 키는 검증으로 발급 주체를 확인한 뒤 조회할 수 있습니다/);
  assert.doesNotMatch(waiting, /지금 조회/);
  assert.match(card({ hint: "ASIA••••••••DEMO" }, { principal: "arn:aws:iam::123456789012:role/app" }), /지금 조회/);
  assert.match(card({}, {}), /지금 조회/);
  assert.doesNotMatch(card({ hint: "ASIA••••••••DEMO" }, { canLookup: false, principal: null }), /지금 조회|세션 키는/);
  // While the detail loads the principal is not known yet: neither the note nor the button.
  assert.doesNotMatch(card({ hint: "ASIA••••••••DEMO" }, {}), /지금 조회|세션 키는/);
  assert.equal(card({ hint: "ghp_••••" }, {}), "");  // no lookup for this service: no card
  const unverified = html(React.createElement(usage.UsageBody, { u: snapshot({ collection_status: "ACCOUNT_UNVERIFIED" }), canLookup: true }));
  assert.match(unverified, /관측된 호출<\/dt><dd>—<\/dd>/);
  assert.ok(!unverified.includes("조회 기간의 관리 이벤트에 이 키로 한 호출이 없습니다."));
  const source_ = source("@/console/views/credentials/usage.tsx");
  assert.match(source_, /사용 기록 수집을 접수했습니다/);
});

test("background totals and service counts include calls beyond the recent detail sample", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  const large = snapshot({ events: [event({})], summary: { events: 10051, denied: 3, techniques: {},
    services: { s3: { service: "s3", calls: 10051, writes: 2, denied: 3, last: null } } } });
  const markup = html(React.createElement(usage.UsageBody, { u: large, canLookup: true }));
  assert.match(markup, /10051건 · 거부 3건/);
  assert.match(markup, /최근 호출 · 10051건 중 1건/);
  assert.match(markup, /상세 기록은 최근 100건까지/);
  for (const status of ["QUEUED", "RUNNING", "CANCELLING"]) {
    assert.match(usage.usageStatusText({ ...large, refresh_job: { id: "j", status } }, L, true), /백그라운드/);
  }
  assert.match(usage.usageStatusText({ ...large, refresh_job: { id: "j", status: "CANCELLED" } }, L, true), /중단됐습니다/);
  assert.match(usage.usageStatusText({ ...large, refresh_job: { id: "j", status: "RUNNING", error_code: "AWS_LOGIN_REQUIRED" } }, L, true), /저장한 위치부터/);
});

test("the addresses a key was used from show per call and as the recent sources; an AWS service host is not called an IP", () => {
  const usage = load("@/console/views/credentials/usage.tsx");
  const cells = load("@/console/views/credentials/cells.tsx");
  const records = load("@/console/records.ts");
  assert.equal(records.sourceLabel("203.0.113.5", "IPV4", L), "203.0.113.5");
  assert.equal(records.sourceLabel("cloudtrail.amazonaws.com", "AWS_INTERNAL", L), "AWS 서비스 cloudtrail.amazonaws.com");
  assert.equal(records.sourceLabel("cloudtrail.amazonaws.com", "AWS_INTERNAL", (ko, en) => en), "AWS service cloudtrail.amazonaws.com");
  const markup = html(React.createElement(usage.UsageBody, { u: snapshot({ events: [
    event({ source_address: "203.0.113.5", source_address_kind: "IPV4" }),
    event({ source_address: "cloudtrail.amazonaws.com", source_address_kind: "AWS_INTERNAL" }), event({})] }), canLookup: false }));
  assert.match(markup, /<th>출처<\/th>/);
  assert.match(markup, /data-label="출처"><span class="mono">203\.0\.113\.5<\/span>/);
  assert.match(markup, /<span class="mono">AWS 서비스 cloudtrail\.amazonaws\.com<\/span>/);
  assert.match(markup, /data-label="출처"><span class="subtle">—<\/span>/);
  const facts = (fields) => html(React.createElement(cells.RecentSources, { c: record(fields) }));
  assert.equal(facts({}), "");
  assert.equal(facts({ recent_sources: [] }), "");
  const shown = facts({ recent_sources: [{ address: "203.0.113.5", kind: "IPV4", last_seen_at: "2026-10-04T05:03:00+00:00", count: 3 },
    { address: "cloudtrail.amazonaws.com", kind: "AWS_INTERNAL", last_seen_at: null, count: 1 }] });
  assert.match(shown, /최근 사용 출처/);
  assert.match(shown, /203\.0\.113\.5<\/span>[\s\S]*?3건/);
  assert.match(shown, /AWS 서비스 cloudtrail\.amazonaws\.com<\/span>[\s\S]*?—[\s\S]*?1건/);
  assert.doesNotMatch(shown, /\+\d/);  // no total: nothing past the listed addresses is claimed
  // The API lists five; the total counts every distinct address in every event the lookup read.
  const five = Array.from({ length: 5 }, (_, n) => ({ address: `192.0.2.${n}`, kind: "IPV4", last_seen_at: null, count: 1 }));
  const rest = (fields, locale) => html(React.createElement(cells.RecentSources, { c: record({ recent_sources: five, ...fields }) }), locale);
  assert.match(rest({ recent_sources_total: 1205 }), /<li class="tag num">\+1,200곳<\/li><\/ul>/);
  assert.match(rest({ recent_sources_total: 9 }, "en"), /<li class="tag num">\+4 more<\/li><\/ul>/);
  // Addresses past what the lookup could count: the total is a lower bound.
  assert.match(rest({ recent_sources_total: 256, recent_sources_more: true }), /<li class="tag num">\+251곳 이상<\/li>/);
  assert.match(rest({ recent_sources_total: 256, recent_sources_more: true }, "en"), /<li class="tag num">\+251 or more<\/li>/);
  assert.doesNotMatch(rest({ recent_sources_total: 5, recent_sources_more: false }), /\+\d|더 있을 수 있음/);
  // A lower bound with none known past those listed (a lookup saved before every address was counted): no "+0".
  for (const [locale, hint] of [["ko", "더 있을 수 있음"], ["en", "possibly more"]]) {
    const markup = rest({ recent_sources_total: 5, recent_sources_more: true }, locale);
    assert.match(markup, new RegExp(`<li class="tag">${hint}</li></ul>`));
    assert.doesNotMatch(markup, /\+\d/);
  }
  // Both key-fact lists (the overview and the exposed-credential panel) carry it beside the last use.
  assert.equal((source("@/console/views/credentials/tabs.tsx").match(/<RecentSources c=\{c\} \/>/g) ?? []).length, 2);
});
