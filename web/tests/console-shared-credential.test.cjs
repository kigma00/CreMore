// One credential that both collects and acts (cremore.onboarding.service.shared_credentials): the console says so
// on both integrations, where the credential is entered, and with the plan. Nothing is refused. Synthetic rows only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const ko = (k, e) => k;
const en = (k, e) => e;

const connection = (purposes, sharedWith, status = "ACTIVE", extra = {}) => ({
  id: purposes[0], provider: "gitlab", edition: "cloud", name: `GitLab · ${purposes[0]}`, status, revision: 3,
  purposes, plans: Object.fromEntries(purposes.map(p => [p, {}])), auth_method: "token", renewal: "ROTATES",
  credential: { roles: ["credential"], reference: false, shared_with: sharedWith }, children: [], target: { scope: "group", id: "10" },
  checks: { results: {}, checked_at: "2026-09-30T02:00:00Z", requested_at: "2026-09-30T01:00:00Z", job_id: null, stale: false, error: null },
  ...extra,
});

test("an integration that shares its credential across the line needs attention, on both sides", () => {
  const acting = connection(["remediation"], [{ id: "inventory", name: "GitLab · inventory" }]);
  const state = model.rowState(acting, [], ko);
  assert.equal(state.tone, "warn");
  assert.equal(state.fix, "credential");  // "Change credential": the credential step of the wizard
  assert.equal(state.note, "수집 연동 'GitLab · inventory'도 이 자격증명을 씁니다 · 조치용은 따로 두세요");
  const collecting = connection(["inventory"], [{ id: "remediation", name: "GitLab · remediation" }]);
  assert.equal(model.sharedNote(collecting, en), "Acting integration 'GitLab · remediation' uses this credential too · give collection its own");
  // A row still being set up keeps its own next step; the page shows the shared credential on its own line.
  assert.equal(model.rowState(connection(["remediation"], [{ id: "x", name: "X" }], "CHECKED"), [], ko).fix, "resume");
  assert.equal(model.rowState(connection(["remediation"], []), [], ko).tone, "ok");
  assert.equal(model.sharedNote(connection(["inventory"], undefined), ko), "");
});

test("many sharers read as a short list, in either language", () => {
  const many = connection(["remediation"], ["A", "B", "C", "D"].map(name => ({ id: name, name })));
  assert.equal(model.sharedNote(many, ko), "수집 연동 'A', 'B' 외 2개도 이 자격증명을 씁니다 · 조치용은 따로 두세요");
  assert.equal(model.sharedNote(many, en), "Collecting integrations 'A', 'B' and 2 more use this credential too · give actions their own");
});

test("the worker's own Google Cloud identity is moved on the acting side", () => {
  const adc = { provider: "gcp", auth_method: "adc" };
  const collecting = connection(["inventory"], [{ id: "act", name: "Google Cloud · act" }], "ACTIVE", adc);
  assert.match(model.sharedNote(collecting, ko), /워커 자신의 Google Cloud 신원\(ADC\).*Google 로그인으로 바꾸세요/);
  assert.equal(model.sharedFix(collecting), "act");  // the collection cannot change the worker's identity
  const acting = connection(["remediation"], [{ id: "inventory", name: "Google Cloud · inv" }], "ACTIVE", adc);
  assert.equal(model.sharedFix(acting), "remediation");
  assert.equal(model.sharedFix(connection(["inventory"], [{ id: "r", name: "R" }])), "inventory");  // a token: its own
});

test("the note shows on the row whatever else it says, where the credential is entered, and with a plan", () => {
  const page = source("@/console/views/integrations/page.tsx");
  assert.match(page, /state\.fix !== "credential" && c\.status !== "DISABLED" && sharedNote\(c, L\)/);
  assert.match(page, /kind === "credential"\) setWizard\(\{ id: sharedFix\(c\), step: 2 \}\)/);
  const wizard = source("@/console/views/integrations/wizard.tsx");
  assert.match(wizard, /conn && checkedNow && sharedNote\(conn, L\) \? <Banner tone="warn"/);
  const plans = source("@/console/views/approvals/plans.tsx");
  assert.match(plans, /policy\.remediation_connection\?\.shared_with\?\.length \? <Banner tone="warn"/);
});
