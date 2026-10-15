// The machine identity window: what the integrations card says, how a binding's state is read from the
// processes' reports, the body a save sends (an empty secret keeps the saved one), and the setup step the
// cloud and Vault sign-ins offer. Synthetic views only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const machine = load("@/console/views/integrations/machine.tsx");
const guide = load("@/console/views/integrations/guide.tsx");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));
const NOW = Date.parse("2026-09-29T03:00:00Z");

const view = (changes = {}) => ({
  configured: true, revision: 2, secret_saved: true,
  idp: { token_url: "https://idp.example.test/oauth2/aus1/v1/token", client_id: "0oa-cremore", auth_method: "client_secret_post", token_field: "access_token", scope: "cremore.workload", audience: null },
  aws: { enabled: true, role_arn: "arn:aws:iam::123456789012:role/CreMoreIdp", scope: null, audience: null },
  gcp: { enabled: false, provider: "", service_account: "", scope: null, audience: null },
  azure: { enabled: false, tenant: "", client_id: "", scope: null, audience: null },
  vault: [{ name: "pay", scope: null, audience: null }], processes: [], test: null, ...changes,
});

test("the integrations card names the clouds the identity reaches", () => {
  assert.equal(machine.machineState(undefined, L), "설정 안 됨");
  assert.equal(machine.machineState(view(), L), "AWS · Vault");
  assert.equal(machine.machineState(view({ aws: { ...view().aws, enabled: false }, vault: [] }), L), "꺼짐");
});

test("a binding reads ready only when every recent process holds its token", () => {
  const report = (process, state, at = "2026-09-29T02:59:00Z") => ({ process, revision: 2, error: null, reported_at: at,
    tokens: { aws: { state, code: state === "FAILED" ? "OAUTH_TOKEN_REQUEST_FAILED" : null } } });
  assert.equal(machine.bindingState(view(), "aws", NOW).tone, "none");
  assert.equal(machine.bindingState(view({ processes: [report("api:h", "READY"), report("worker:1", "READY")] }), "aws", NOW).tone, "ok");
  assert.equal(machine.bindingState(view({ processes: [report("api:h", "READY"), report("worker:1", "FAILED")] }), "aws", NOW).tone, "bad");
  // A process silent for over a day no longer counts.
  assert.equal(machine.bindingState(view({ processes: [report("worker:old", "FAILED", "2026-09-27T00:00:00Z"), report("api:h", "READY")] }), "aws", NOW).tone, "ok");
  assert.equal(machine.processName("worker:abc", L), "워커");
  assert.equal(machine.codeText("OAUTH_TOKEN_REQUEST_FAILED: status", L), "IdP가 토큰을 주지 않았습니다. 클라이언트 ID·비밀·scope를 확인하세요.");
});

test("a save sends trimmed fields, nulls for empty options, and no secret unless one was typed", () => {
  const form = { token_url: " https://idp.example.test/token ", client_id: "0oa-cremore", secret: "", auth_method: "client_secret_basic",
    token_field: "access_token", scope: "", audience: " api://cremore ", aws: true, role_arn: " arn:aws:iam::123456789012:role/CreMoreIdp ",
    gcp: false, provider: "", service_account: "", azure: false, tenant: "", azure_client: "", vault: [{ name: "pay", audience: "" }, { name: " ", audience: "x" }] };
  const body = plain(machine.machineBody(form, 3));
  assert.equal(body.expected_revision, 3);
  assert.equal(body.client_secret, null);
  assert.deepEqual(body.idp, { token_url: "https://idp.example.test/token", client_id: "0oa-cremore", auth_method: "client_secret_basic", token_field: "access_token", scope: null, audience: "api://cremore" });
  assert.equal(body.aws.role_arn, "arn:aws:iam::123456789012:role/CreMoreIdp");
  assert.deepEqual(body.vault, [{ name: "pay", audience: null }]);
});

test("the cloud and Vault sign-ins offer the machine identity among their setup steps", () => {
  let opened = 0;
  const context = { openMachine: () => { opened++; } };
  const step = provider => guide.guideSteps({ provider }, { id: { gcp: "adc", azure: "workload_identity", entra_id: "workload_identity", vault: "jwt", openbao: "jwt" }[provider] }, null, context, L);
  for (const provider of ["gcp", "azure", "entra_id", "vault", "openbao"]) {
    const steps = step(provider);
    assert.equal(steps.at(-1).key, "machine", provider);
    assert.equal(steps.at(-1).actions[0].kind, "open");
  }
  step("gcp").at(-1).actions[0].onOpen();
  assert.equal(opened, 1);
  // A token a person types, or a customer-side CLI, has nothing to do with the machine identity.
  assert.deepEqual(plain(guide.guideSteps({ provider: "vault" }, { id: "token" }, null, context, L)), []);
  assert.deepEqual(plain(guide.guideSteps({ provider: "gitlab" }, { id: "token" }, null, context, L)), []);
});
