"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

test("every chain state and problem the integrity check names reads in words", () => {
  const audit = load("@/console/views/audit.tsx");
  for (const state of ["INTACT", "BROKEN", "ANCHOR_MISMATCH", "UNAUTHENTICATED", "NOT_STARTED"]) assert.ok(audit.CHAIN_STATE[state], state);
  // The kinds docs/API.md lists for GET /api/v1/audit/integrity.
  for (const kind of ["SEQUENCE_GAP", "SEQUENCE_INVALID", "MAC_MISMATCH", "ANCHOR_CLAIM_MISMATCH", "ANCHOR_SEQUENCE_GAP", "CHAIN_REWOUND",
    "CHAIN_RESET", "GENESIS_MISSING", "GENESIS_INVALID", "GENESIS_MOVED", "KEY_MISMATCH", "UNAUTHENTICATED"]) {
    assert.equal(audit.PROBLEM[kind].length, 4, kind);
  }
  assert.equal(audit.CHAIN_STATE.BROKEN.tone, "bad");
  assert.equal(audit.CHAIN_STATE.INTACT.tone, "ok");
});

// Every event type the backend writes into the audit trail (the 2026-09-30 list; finding events arrive FINDING_-prefixed).
// Types passed through a helper are listed by hand (RESPONSE_LINK_SENT and RESPONSE_NOT_SENT go through the response
// lifecycle's _save); a literal event_type="..." anywhere in the backend is found below.
const EVENTS = `RESPONSE_REQUESTED RESPONSE_TICKET_OPENED RESPONSE_LATE_TICKET_OPENED RESPONSE_SEND_UNKNOWN RESPONSE_TICKET_CHECKED RESPONSE_ANSWER_REFUSED RESPONSE_CLEANUP_DECLARED RESPONSE_DECLINED RESPONSE_SEND_RELEASED RESPONSE_REMOVAL_VERIFIED RESPONSE_REAPPEARED RESPONSE_STILL_EXPOSED
RESPONSE_LINK_SENT RESPONSE_NOT_SENT
AUTH_SESSION_OBSERVED API_REQUEST_STARTED API_REQUEST_SUCCEEDED API_REQUEST_ACCEPTED API_REQUEST_DENIED API_REQUEST_FAILED
ROLLUP_UPDATED ACKNOWLEDGED RESOLVED REOPENED FALSE_POSITIVE IGNORED ASSIGNED AUTO_FALSE_POSITIVE
AUTO_FALSE_POSITIVE_REOPENED RISK_REEVALUATED COMMENT TAGS_CHANGED STAGE_CHANGED REMEDIATION_STEP OWNERSHIP_REVIEW_UPDATED
OWNER_CONTACTED OWNER_CONTACT_SENT OWNER_CONTACT_FAILED CONTACT_DELIVERY_SAVED CONTACT_DELIVERY_TESTED TICKET_CREATED
TICKET_UPDATED TICKET_APPROVED TICKET_SYSTEM_SAVED TICKET_SYSTEM_CHECKED MANAGEMENT_ACTION_REQUESTED MANAGEMENT_ACTION_CONFIRMED
MANAGEMENT_ACTION_REFUSED ACTION_PLAN_REQUESTED ACTION_PLAN_APPROVED ACTION_PLAN_CANCELLED ACTION_PLAN_QUEUED
ACTION_PLAN_EXECUTION_STARTED ACTION_PLAN_VERIFIED ACTION_PLAN_FAILED ACTION_PLAN_OUTCOME_UNKNOWN ACTION_PLAN_RECHECKED
ACTION_PLAN_RECHECK_REQUESTED ACTION_PLAN_REFUSED ACTION_PLAN_EMERGENCY OWNER_APPROVAL_REQUESTED OWNER_APPROVAL_NOT_SENT
OWNER_APPROVAL_TICKET_OPENED OWNER_APPROVAL_TICKET_REFUSED OWNER_APPROVAL_GRANTED OWNER_APPROVAL_DECLINED OWNER_APPROVAL_RECORDED
OWNER_NOTIFIED_AFTER OWNER_NOTICE_NOT_SENT OWNER_APPROVAL_POLICY_CHANGED PROVIDER_CONNECTION_CREATED
PROVIDER_CONNECTION_CHECK_REQUESTED PROVIDER_CONNECTION_ACTIVATED PROVIDER_CONNECTION_PLAN_CHANGED
PROVIDER_CONNECTION_CREDENTIAL_CHANGED PROVIDER_CONNECTION_ENABLED PROVIDER_CONNECTION_DISABLED PROVIDER_CONNECTION_DELETED
PROVIDER_CONNECTION_CREDENTIAL_RENEWED PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED PROVIDER_CONNECTION_CREDENTIAL_RETIRED
PROVIDER_CONNECTION_RECORD_TAKEN_OVER PROVIDER_CONNECTION_RECORD_ADOPTED GITHUB_ENTERPRISE_INSTALL_REQUESTED
GITHUB_ENTERPRISE_INSTALL_CANCELLED GITHUB_ENTERPRISE_AUTO_INSTALL_ON GITHUB_ENTERPRISE_AUTO_INSTALL_OFF GITHUB_ENTERPRISE_AUTO_QUEUED
GITHUB_ENTERPRISE_ORG_INSTALLED GITHUB_ENTERPRISE_ORG_CONNECTED GITHUB_ENTERPRISE_ORG_ACTIVATED GITHUB_ENTERPRISE_ORG_INSTALL_FAILED
GITHUB_ENTERPRISE_KEY_PROPAGATED GITHUB_ENTERPRISE_STOPPED_WITH_SOURCE GITHUB_APP_MANIFEST_STARTED GITHUB_APP_MANIFEST_CREATED
GITHUB_APP_MANIFEST_COMPLETED GCP_OAUTH_CLIENT_SAVED GCP_OAUTH_STARTED GCP_OAUTH_AUTHORIZED GCP_OAUTH_CONNECTED
METADATA_CONNECTION_CREATED COVERAGE_CONNECTION_CREATED COLLECTION_PLAN_CHANGED COLLECTION_TURNED_OFF_BY_PLAN
METADATA_CONNECTION_CHANGED METADATA_COLLECTION_REQUESTED METADATA_COLLECTION_PAUSED METADATA_COLLECTION_RESUMED
METADATA_COLLECTION_STOP_REQUESTED METADATA_COLLECTION_SCHEDULED GCP_VALUES_READ FORWARDED_TO_SIEM SIEM_TEST_EVENT_QUEUED
SIEM_HELD_RELEASED DOMAIN_ADDED DOMAIN_INTERNAL_CHANGED DOMAIN_CHALLENGE_RENEWED DOMAIN_REMOVED DOMAIN_VERIFIED
DOMAIN_VERIFICATION_FAILED DOMAIN_LAPSED MACHINE_IDENTITY_CHANGED LEAVER_LINK_CONFIRMED LEAVER_LINK_REJECTED LEAVER_LINK_CLEARED
LEAVER_EVALUATED AWS_SSO_LOGIN_STARTED AWS_SSO_LOGIN_DONE AWS_SSO_LOGIN_EXPIRED AWS_SSO_LOGIN_DENIED AWS_SSO_LOGIN_FAILED
AUDIT_CHAIN_STARTED AUDIT_CHAIN_ANCHORED AUDIT_CHAIN_REWOUND AUDIT_CHAIN_ACKNOWLEDGED CONNECTION_STOPPED
CONNECTION_EXPIRY_DECLARED CONNECTION_EXPIRY_CLEARED INSTALLATION_SETTING_CHANGED LEARNED_FP_PROFILE_STOPPED LEARNED_FP_PROFILE_RESET`.split(/\s+/);
const TARGETS = ["finding", "connection", "provider_connection", "coverage_connection", "action_plan", "credential", "orphan",
  "coverage_entity", "contact_delivery", "ticket_system", "owner_approval_policy", "github_app_manifest", "gcp_oauth", "siem_event",
  "siem_destination", "domain", "machine_identity", "identity_person", "identity_check", "aws_sso_login", "audit_chain", "connection_health",
  "installation_setting", "learned_fp_profile", "api_request", "sign_in", "response_channels"];

/** event_type="..." written anywhere in the backend (tests excluded). */
function literalEvents() {
  const root = path.join(__dirname, "..", "..");
  const found = new Set();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (!["node_modules", "__pycache__", ".venv", "standalone"].includes(entry.name)) walk(full); continue; }
      if (!entry.name.endsWith(".py") || entry.name.endsWith("_test.py") || entry.name === "conftest.py") continue;
      for (const match of fs.readFileSync(full, "utf8").matchAll(/event_type\s*=\s*["']([A-Z][A-Z0-9_]+)["']/g)) found.add(match[1]);
    }
  };
  walk(path.join(root, "cremore"));
  for (const vendor of fs.readdirSync(root)) {
    const backend = path.join(root, vendor, "backend");
    if (fs.existsSync(backend)) walk(backend);
  }
  return found;
}

test("every audit event and target the backend writes reads in both languages", () => {
  const labels = load("@/components/labels.tsx");
  const literal = literalEvents();
  // Retiring the GCP raw-value read route removed its writer; historical GCP_VALUES_READ labels remain above.
  assert.ok(literal.size >= 39 && literal.has("INSTALLATION_SETTING_CHANGED"), "the backend scan found the literal event types");
  const events = new Set([...EVENTS, ...literal]);
  assert.ok(events.size >= 120);
  for (const locale of ["ko", "en"]) {
    for (const code of events) {
      const text = labels.auditActionText(code, locale);
      assert.notEqual(text.label, code.replaceAll("_", " "), `${code} has no ${locale} label`);
      assert.equal(labels.auditActionText(`FINDING_${code}`, locale).label, text.label);
    }
    for (const target of TARGETS) assert.notEqual(labels.auditTargetLabel(target, locale), target, `${target} has no ${locale} label`);
    // CreMore's own processes are named, not all read as one "System".
    for (const actor of ["system:ticketing", "system:onboarding", "system:github-enterprise", "system:contact", "system:identity-leavers"]) {
      assert.notEqual(labels.auditActorLabel(actor, locale), actor, actor);
    }
  }
});

test("only problems still open are accepted, with a one-line reason", () => {
  const audit = load("@/console/views/audit.tsx");
  const open = [{ ack: "MAC_MISMATCH@seq:4#a" }, { ack: "UNAUTHENTICATED@seq:9#b" }];
  // A pick another Admin already accepted, or a new read replaced, drops out.
  assert.deepEqual([...audit.stillOpen(["MAC_MISMATCH@seq:4#a", "MAC_MISMATCH@seq:4#old", "SEQUENCE_GAP@seq:2#c"], open)], ["MAC_MISMATCH@seq:4#a"]);
  assert.deepEqual([...audit.stillOpen([], open)], []);
  assert.equal(audit.oneLine("  written by\nthe old API\r\n during the upgrade "), "written by the old API during the upgrade");
  assert.equal(audit.oneLine(" \n\t "), "");
});

test("the audit screen is the console's, reads its three sources and accepts only open problems with a reason", () => {
  const app = source("@/console/app.tsx");
  assert.match(app, /audit: Audit,/);
  const screen = source("@/console/views/audit.tsx");
  assert.match(screen, /useApi<AuditRow\[\]>\(`audit\?limit=\$\{AUDIT_LIMIT\}`\)/);
  assert.match(screen, /api<unknown>\(`v2\/coverage\/events\?\$\{query\}`\)\.then\(value => \{/);
  assert.match(screen, /try \{ setData\(metadataEvents\(value\)\); \} catch \{ setError\(UNREADABLE\); \}/);
  assert.match(screen, /useApi<Integrity>\("audit\/integrity"\)/);
  // Only an Admin, only a problem still open that the check gave a key for; whole-chain problems have none.
  assert.match(screen, /const acceptable = \(problem: ChainProblem\) => admin && !problem\.acknowledged && Boolean\(problem\.ack\)/);
  assert.match(screen, /const chosen = stillOpen\(picked, open\);/);
  assert.match(screen, /<AcceptModal items=\{chosen\}/);
  assert.match(screen, /send<\{ acknowledged: number \}>\("audit\/integrity\/acknowledge", "POST", \{ items, reason: oneLine\(reason\) \}\)/);
  assert.match(screen, /disabled=\{busy \|\| !oneLine\(reason\)\}/);
});
