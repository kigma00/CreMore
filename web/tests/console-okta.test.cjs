// Okta with a key CreMore made, in the console: the setup steps show only the public JWK to paste, the Admin
// Console link follows the org's host, and a made key is not read as a certificate. Synthetic connections only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const guide = load("@/console/views/integrations/guide.tsx");
const copy = load("@/console/views/integrations/copy.ts");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));

const METHOD = { id: "made_key", label: "Service app with a key CreMore makes", label_ko: "서비스 앱(CreMore가 만든 키)", renewal: "AUTOMATIC",
  generated: true, reference: false, purposes: ["identity"], fields: [{ name: "client_id", label: "Client ID", label_ko: "클라이언트 ID", kind: "text", public: true }] };
const OKTA = { provider: "okta", label: "Okta", label_ko: "Okta", category: "identity", target: [], editions: [{ id: "cloud", label: "Okta", label_ko: "Okta" }],
  purposes: { identity: { permissions: [{ id: "users_read", label: "okta.users.read", label_ko: "okta.users.read" }] } }, auth_methods: [METHOD] };
const PUBLIC = { kty: "RSA", e: "AQAB", n: "synthetic-modulus", kid: "synthetic-kid-0001", alg: "RS256", use: "sig" };
const connection = generated => ({
  id: "o1", provider: "okta", edition: "cloud", name: "Okta · acme.okta.com", status: "CHECKED", revision: 1, purposes: ["identity"], plans: {},
  auth_method: "made_key", credential: { roles: ["credential"], reference: false }, children: [],
  target: { organization: "acme.okta.com", auth: { client_id: "0oa1serviceapp" }, ...(generated ? { generated } : {}) },
  checks: { results: {}, checked_at: null, requested_at: null, job_id: null, stale: false, error: null },
});

test("the steps end with the public key to paste and the grants", () => {
  assert.deepEqual(plain(guide.guideSteps(OKTA, METHOD, null, {}, L).map(step => step.key)), ["app"]);
  const made = { public_jwk: PUBLIC, kid: PUBLIC.kid, created_at: "2026-09-29T03:00:00+00:00" };
  const steps = guide.guideSteps(OKTA, METHOD, connection(made), {}, L);
  assert.deepEqual(plain(steps.map(step => step.key)), ["app", "key", "grants"]);
  assert.equal(steps[0].actions[0].href, "https://acme-admin.okta.com/admin/apps/active");
  assert.deepEqual(JSON.parse(steps[1].actions[0].text), PUBLIC);
  assert.match(steps[1].text, /kid synthetic-kid-0001/);
  assert.match(steps[2].text, /okta\.users\.read를 Grant하고\(Grant는 Super Admin만 할 수 있습니다\), Admin roles 탭에서 사용자 보기만 있는 역할/);
  // Okta's guide: Applications and Resources > Applications > Create App Integration.
  assert.match(steps[0].text, /Applications and Resources → Applications → Create App Integration/);
  // Only the public members are copied, whatever else the stored part holds.
  const extra = guide.guideSteps(OKTA, METHOD, connection({ ...made, public_jwk: { ...PUBLIC, d: "not-public" } }), {}, L);
  assert.deepEqual(JSON.parse(extra[1].actions[0].text), PUBLIC);
  // A key made again: the earlier one stays valid at Okta until it is deactivated and deleted there.
  const again = guide.guideSteps(OKTA, METHOD, connection({ ...made, previous: { kid: "earlier-kid-0001" } }), {}, L);
  assert.deepEqual(plain(again.map(step => step.key)), ["app", "key", "grants", "retire"]);
  assert.match(again[3].text, /이전 키\(kid earlier-kid-0001\)를 Deactivate한 뒤 삭제/);
});

test("a made key is its own kind, and the admin console link needs an Okta host", () => {
  const made = { public_jwk: PUBLIC, kid: PUBLIC.kid, created_at: "2026-09-29T03:00:00+00:00" };
  assert.equal(model.madeKeyOf(connection(made)).kid, PUBLIC.kid);
  assert.equal(model.generatedOf(connection(made)), null);
  assert.equal(model.madeKeyOf(connection(null)), null);
  assert.equal(guide.oktaAdmin("acme.oktapreview.com"), "https://acme-admin.oktapreview.com/admin/apps/active");
  assert.equal(guide.oktaAdmin("login.acme.example"), null);
  assert.equal(guide.oktaAdmin("acme.okta-mil.com"), null);  // not an Okta domain (the server refuses it too)
  assert.equal(guide.oktaAdmin(" https://ACME.okta.com/ "), "https://acme-admin.okta.com/admin/apps/active");
  // Before the connection exists, the typed host names the console.
  const first = guide.guideSteps(OKTA, METHOD, null, { target: { organization: "acme.okta.com" } }, L);
  assert.equal(first[0].actions[0].href, "https://acme-admin.okta.com/admin/apps/active");
  assert.match(copy.methodHint("okta", METHOD, L), /공개 키\(JWK\)만 붙여 넣습니다/);
  assert.match(model.detailText("OKTA_TOKEN_REFUSED", L), /공개 키·클라이언트 ID·권한 확인/);
});
