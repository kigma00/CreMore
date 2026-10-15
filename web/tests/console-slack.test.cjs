// Slack in the console: the setup steps start from a link that makes the org-ready app from a manifest with the
// scopes the chosen options need, and a permission tied to an option counts only while the option is on.
// Synthetic descriptor and connections only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const guide = load("@/console/views/integrations/guide.tsx");
const model = load("@/console/views/integrations/model.ts");
const ko = (text, _en) => text;
const en = (_ko, text) => text;
const plain = value => JSON.parse(JSON.stringify(value));

const SLACK = {
  provider: "slack", label: "Slack", label_ko: "Slack", category: "saas", target: [],
  editions: [{ id: "cloud", label: "Slack Enterprise Grid", label_ko: "Slack Enterprise Grid" }],
  purposes: { inventory: {
    permissions: [
      { id: "admin_apps_read", label: "admin.apps:read scope", label_ko: "admin.apps:read 범위" },
      { id: "auditlogs_read", label: "auditlogs:read scope", label_ko: "auditlogs:read 범위", option: "audit_events" },
    ],
    plan: [{ name: "audit_events", kind: "bool", default: false, label: "Audit log", label_ko: "감사 로그" }],
  } },
  auth_methods: [{ id: "token", label: "Admin app token", label_ko: "관리자 앱 토큰", renewal: "NONE", purposes: ["inventory"], fields: [] }],
};
const METHOD = SLACK.auth_methods[0];

function manifestOf(step) {
  const url = new URL(step.actions[0].href);
  assert.equal(url.origin + url.pathname, "https://api.slack.com/apps");
  assert.equal(url.searchParams.get("new_app"), "1");
  return JSON.parse(url.searchParams.get("manifest_json"));
}

test("the app link carries the scopes the options need, org-wide install and no token rotation", () => {
  for (const context of [{}, { plans: { inventory: { audit_events: false } } }]) {
    const steps = guide.guideSteps(SLACK, METHOD, null, context, ko);
    assert.deepEqual(plain(steps.map(step => step.key)), ["app", "install", "token"]);
    const manifest = manifestOf(steps[0]);
    assert.deepEqual(plain(manifest.oauth_config.scopes.user), ["admin.apps:read"]);
    // Organization-wide install needs one bot scope, and a bot scope needs a bot user.
    assert.deepEqual(plain(manifest.oauth_config.scopes.bot), ["team:read"]);
    assert.equal(manifest.features.bot_user.display_name, "CreMore");
    assert.deepEqual(plain(manifest.settings), { org_deploy_enabled: true, token_rotation_enabled: false });
    assert.ok(manifest.display_information.name.length <= 35 && manifest.display_information.description.length <= 140);
    assert.doesNotMatch(steps[1].text, /설치해야/);
  }
  const audit = guide.guideSteps(SLACK, METHOD, null, { plans: { inventory: { audit_events: true } } }, ko);
  assert.deepEqual(plain(manifestOf(audit[0]).oauth_config.scopes.user), ["admin.apps:read", "auditlogs:read"]);
  assert.match(audit[1].text, /조직 소유자\(Owner\)가 설치해야 합니다/);
  const english = guide.guideSteps(SLACK, METHOD, null, { plans: { inventory: { audit_events: true } } }, en);
  assert.match(english[1].text, /Owner must install it/);
  assert.match(english[0].text, /team:read/);
});

test("a stored token's app is kept: the audit option adds its scope there instead of a new app", () => {
  assert.equal(guide.guideSteps(SLACK, METHOD, null, { stored: true, plans: { inventory: { audit_events: false } } }, ko).length, 0);
  const steps = guide.guideSteps(SLACK, METHOD, null, { stored: true, plans: { inventory: { audit_events: true } } }, ko);
  assert.deepEqual(plain(steps.map(step => step.key)), ["scope"]);
  assert.match(steps[0].text, /auditlogs:read를 더하고, 조직 소유자\(Owner\)가 조직에 다시 설치/);
});

test("a permission tied to an option counts only while the option is on", () => {
  const ids = plan => plain(model.permissionsFor(SLACK, "inventory", "token", {}, plan).map(permission => permission.id));
  assert.deepEqual(ids({ audit_events: false }), ["admin_apps_read"]);
  assert.deepEqual(ids({ audit_events: true }), ["admin_apps_read", "auditlogs_read"]);
  assert.deepEqual(ids(undefined), ["admin_apps_read", "auditlogs_read"]);
  const conn = (status, plans) => ({
    id: "s1", provider: "slack", edition: "cloud", name: "Slack · E0SYNTH01", status, revision: 2, purposes: ["inventory"], plans,
    auth_method: "token", credential: { roles: ["credential"], reference: false }, children: [], target: { organization: "E0SYNTH01" },
    checks: { checked_at: "2026-09-29T02:00:00Z", requested_at: "2026-09-29T01:00:00Z", job_id: null, stale: false, error: null,
      results: { inventory: { status: "MISSING", items: [{ permission: "admin_apps_read", status: "GRANTED" },
        { permission: "auditlogs_read", status: "MISSING", detail: "SLACK_SCOPE_MISSING" }] } } },
  });
  // Checked, the audit option not chosen yet (its default is off): nothing is missing.
  assert.equal(model.rowState(conn("CHECKED", {}), [], ko, undefined, SLACK).note, "권한을 확인했습니다 · 수집 범위를 정하면 시작합니다");
  assert.equal(model.rowState(conn("ACTIVE", { inventory: { audit_events: false } }), [], ko, undefined, SLACK).tone, "ok");
  const on = model.rowState(conn("ACTIVE", { inventory: { audit_events: true } }), [], ko, undefined, SLACK);
  assert.equal(on.tone, "warn");
  assert.equal(on.note, "권한 확인에서 1개가 없었습니다");
  // Without the descriptor every answer counts, as before.
  assert.equal(model.checkItems(conn("ACTIVE", {})).length, 2);
  assert.equal(model.checkItems(conn("ACTIVE", {}), ["inventory"], SLACK, { inventory: { audit_events: true } }).length, 2);
});
