// Credential groups are UI work items, never combined backend identities.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const { setupGroups } = load("@/console/views/integrations/setup.ts");
const { enabledPurposes, rowState, methodsFor, forCollectionEntry, purposesForEdition, scanEntryOf } = load("@/console/views/integrations/model.ts");
const plain = value => JSON.parse(JSON.stringify(value));
const E = "exposure", I = "inventory", V = "vault", P = "identity", R = "remediation";
// Minimal method/purpose contracts for every currently registered provider; no sample customer data.
const contracts = {
  github: { github_app: [E, I, V, R], token: [E, P] }, gitlab: { token: [E, I, V, R] },
  confluence: { service_account: [E], token: [E] }, bitbucket: { access_token: [E, I], http_token: [E, I], api_token: [E, I] },
  atlassian: { api_key: [I] }, notion: { integration: [E], organization_bot: [I, R] }, slack: { token: [I] },
  aws: { role: [E, I, V], sso: [E, I, V], runtime: [E, I, V], customer_cli: [I, V] },
  gcp: { adc: [E, I, V, R], google_oauth: [E, I, V, R], customer_cli: [V] },
  google_workspace: { service_account_delegation: [P] }, azure: { certificate: [E, I, V, P], workload_identity: [E, I, V, P] },
  azure_devops: { token: [E, I, R], server_token: [E] }, entra_id: { workload_identity: [P] },
  vault: { customer_cli: [V], kubernetes: [V], jwt: [V], token: [V] }, openbao: { customer_cli: [V], kubernetes: [V], jwt: [V], token: [V] },
  okta: { made_key: [P], private_key_jwt: [P] }, keycloak: { oauth_client: [P] },
  external_vault: { jsonl: [V], reader: [V] }, website: { none: [E] },
};
for (const [provider, methods] of Object.entries(contracts)) test(`${provider}: every feature combination is covered without sharing acting credentials`, () => {
  const purposes = [...new Set(Object.values(methods).flat())];
  const d = { provider, editions: [{ id: "cloud" }], purposes: Object.fromEntries(purposes.map(p => [p, {}])),
    auth_methods: Object.entries(methods).map(([id, purposes]) => ({ id, purposes })) };
  for (const preferred of Object.keys(methods)) for (let bits = 1; bits < 2 ** purposes.length; bits++) {
    const chosen = purposes.filter((_, i) => bits & (1 << i));
    const groups = plain(setupGroups(d, chosen, "cloud", preferred));
    assert.deepEqual(groups.flatMap(g => g.purposes).sort(), [...chosen].sort());
    for (const g of groups) {
      assert.equal(g.edition, "cloud");
      assert.ok(g.purposes.every(p => methods[g.method].includes(p)));
      if (g.purposes.includes(R)) assert.deepEqual(g.purposes, [R]);
    }
  }
});

test("features never silently switch the chosen edition, and acting credentials remain separate", () => {
  const d = { provider: "notion", editions: [{ id: "cloud" }, { id: "enterprise" }], purposes: { exposure: {}, inventory: {}, remediation: {} },
    auth_methods: [{ id: "integration", editions: ["cloud", "enterprise"], purposes: [E] },
      { id: "organization_bot", editions: ["enterprise"], purposes: [I, R] }] };
  assert.deepEqual(plain(setupGroups(d, [E, I, R], "cloud", "integration")), [
    { method: "integration", edition: "cloud", purposes: [E] },
  ]);
  assert.deepEqual(plain(setupGroups(d, [E, I, R], "enterprise", "integration")), [
    { method: "integration", edition: "enterprise", purposes: [E] },
    { method: "organization_bot", edition: "enterprise", purposes: [I] },
    { method: "organization_bot", edition: "enterprise", purposes: [R] },
  ]);
});

test("account entry authenticates page-only identities on either plan without enabling content or Enterprise inventory", () => {
  const d = { provider: "notion", editions: [{ id: "standard" }, { id: "enterprise" }],
    purposes: { exposure: {}, inventory: { editions: ["enterprise"] } }, auth_methods: [
      { id: "integration", purposes: [E], auth_first: { context: [] } }, { id: "organization_bot", purposes: [I] }] };
  const account = forCollectionEntry(d, "account"), content = forCollectionEntry(d, "exposure");
  assert.deepEqual(plain(methodsFor(account, [], "standard").map(m => [m.id, m.authentication_only])), [["integration", true]]);
  assert.deepEqual(plain(methodsFor(account, [], "enterprise").map(m => m.id)), ["organization_bot", "integration"]);
  assert.deepEqual(plain(methodsFor(account, [I], "standard")), []);
  assert.deepEqual(plain(methodsFor(account, [E], "standard")), []);
  assert.deepEqual(plain(purposesForEdition(account, "standard")), []);
  assert.deepEqual(plain(purposesForEdition(account, "enterprise")), [I]);
  assert.deepEqual(plain(purposesForEdition(content, "enterprise")), [E]);
  assert.deepEqual(plain(setupGroups(content, [E, I], "enterprise", "integration")), [
    { method: "integration", edition: "enterprise", purposes: [E] }]);
});

test("AWS's content-scan card is Amazon S3 with the S3 mark; another service's reads as its content scan", () => {
  const L = (ko) => ko;
  assert.deepEqual(plain(scanEntryOf({ provider: "aws", label: "Amazon Web Services", label_ko: "Amazon Web Services" }, L)), { title: "Amazon S3", logo: "s3" });
  assert.deepEqual(plain(scanEntryOf({ provider: "gitlab", label: "GitLab", label_ko: "GitLab" }, L)), { title: "GitLab · 콘텐츠 검사", logo: "gitlab" });
});

test("retired personal login and uploader methods never enter new setup, but their exact existing owner can be maintained", () => {
  const d = { provider: "aws", editions: [{ id: "cloud" }], purposes: { exposure: {}, inventory: {} },
    auth_methods: [{ id: "sso", new_setup: false, purposes: [E, I] }, { id: "customer_cli", new_setup: false, purposes: [I] },
      { id: "role", purposes: [E, I] }, { id: "runtime", purposes: [E, I] }] };
  assert.deepEqual(plain(methodsFor(d, [], "cloud").map(m => m.id)), ["role", "runtime"]);
  assert.deepEqual(plain(methodsFor(d, [], "cloud", "sso").map(m => m.id)), ["sso", "role", "runtime"]);
  assert.deepEqual(plain(setupGroups(d, [E, I], "cloud", "sso")), [{ method: "role", edition: "cloud", purposes: [E, I] }]);
});

test("redirect storage accepts only bounded current descriptor IDs and drops unrelated properties", () => {
  let value;
  const storage = { getItem: () => value, setItem: (_key, next) => { value = next; }, removeItem: () => { value = null; } };
  const setup = load("@/console/views/integrations/setup.ts", { globals: { sessionStorage: storage } });
  const d = { provider: "notion", editions: [{ id: "cloud" }], purposes: { exposure: {} }, auth_methods: [{ id: "integration", purposes: [E] }] };
  const journey = { provider: "notion", edition: "cloud", expires: Date.now() + 60000, requested: [E], pending: [],
    current: { method: "integration", edition: "cloud", purposes: [E], token: "do-not-keep" }, completed: [], token: "do-not-keep" };
  storage.setItem("", JSON.stringify(journey));
  const read = setup.readJourney(d);
  assert.ok(read); assert.equal(JSON.stringify(read).includes("do-not-keep"), false);
  storage.setItem("", JSON.stringify({ ...journey, pending: Array(6).fill(journey.current) })); assert.equal(setup.readJourney(d), null);
  storage.setItem("", JSON.stringify({ ...journey, current: { ...journey.current, method: "unknown" } })); assert.equal(setup.readJourney(d), null);
  storage.setItem("", JSON.stringify({ ...journey, expires: Date.now() - 1 })); assert.equal(setup.readJourney(d), null);
});

test("all stopped features keep authentication without appearing as active collections", () => {
  const c = { status: "ACTIVE", plans: { exposure: {}, inventory: {} }, feature_enabled: { exposure: false, inventory: false } };
  assert.deepEqual(plain(enabledPurposes(c)), []);
  const state = rowState(c, [], (_ko, en) => en);
  assert.equal(state.tone, "off"); assert.equal(state.label, "All features off"); assert.match(state.note, /retained/);
  assert.deepEqual(plain(enabledPurposes({ ...c, feature_enabled: undefined })), [I, E]);
});
