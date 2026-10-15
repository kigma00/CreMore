"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { load } = require("./load-module.cjs");
const L = (_ko, en) => en;
const tick = () => new Promise(resolve => setImmediate(resolve));
const text = node => typeof node === "string" ? node : !node || typeof node !== "object" ? "" : React.Children.toArray(node.props?.children).map(text).join("");
const elements = (node, match) => !node || typeof node !== "object" ? [] : [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap(child => elements(child, match))];

function mount(module, name, props, overrides = {}) {
  const hooks = []; let cursor = 0, effects = [];
  const react = { ...React,
    useState(initial) { const i = cursor++; if (!(i in hooks)) hooks[i] = typeof initial === "function" ? initial() : initial;
      return [hooks[i], value => { hooks[i] = typeof value === "function" ? value(hooks[i]) : value; }]; },
    useRef(initial) { const i = cursor++; return hooks[i] ||= { current: initial }; },
    useEffect(effect, deps) { const i = cursor++, prior = hooks[i];
      if (!prior || deps.some((value, j) => !Object.is(value, prior.deps[j]))) effects.push(() => { prior?.cleanup?.(); hooks[i] = { deps, cleanup: effect() }; }); },
  };
  const component = load(module, { overrides: { react,
    "@/console/text": { ...load("@/console/text.ts"), useL: () => L },
    "@/console/layer": { ...load("@/console/layer.tsx"), useToast: () => () => {} },
    "@/components/locale": { ...load("@/components/locale.tsx"), useLocale: () => "en" }, ...overrides } })[name];
  return { draw: () => { cursor = 0; effects = []; const tree = component(props); effects.forEach(effect => effect()); return tree; },
    close: () => hooks.forEach(hook => hook?.cleanup?.()) };
}

const planId = "00000000-0000-4000-8000-000000000001", planHash = "a".repeat(64);
const approval = { claims: { plan_id: planId, plan_hash: planHash, mode: "execute" }, signature: "synthetic-signature" };
const file = (value, size) => ({ name: "approval.json", size: size ?? JSON.stringify(value).length, text: async () => JSON.stringify(value) });

test("approval file belongs to the exact plan, content hash and operation; private keys are rejected locally", async () => {
  const changes = [], downloads = [], reads = [];
  const view = mount("@/console/views/approvals/independent-authorization.tsx", "IndependentAuthorization", { planId, planHash, mode: "execute", onChange: value => changes.push(value) }, {
    "@/lib/dashboard-api": { api: async path => { reads.push(path); return { version: 1 }; } },
    "@/console/text": { useL: () => L, downloadJson: (...args) => downloads.push(args) },
  });
  const select = value => elements(view.draw(), e => e.type === "input")[0].props.onChange({ target: { files: value ? [value] : [] } });
  for (const value of [file("-----BEGIN PRIVATE KEY-----"), file(approval, 4097), file({ ...approval, signature: "" }),
    file({ ...approval, claims: { ...approval.claims, plan_id: "other" } }), file({ ...approval, claims: { ...approval.claims, plan_hash: "b".repeat(64) } }),
    file({ ...approval, claims: { ...approval.claims, mode: "emergency" } })]) {
    select(value); await tick(); assert.equal(changes.at(-1), undefined); assert.match(text(view.draw()), /Do not upload a private key/);
  }
  select(file(approval)); await tick(); assert.deepEqual(changes.at(-1), approval);
  select(undefined); assert.equal(changes.at(-1), undefined);
  elements(view.draw(), e => e.type === "button")[0].props.onClick(); await tick();
  assert.deepEqual(reads, [`action-plans/${planId}/authorization-request?mode=execute`]);
  assert.deepEqual(downloads, [[`cremore-authorization-${planId}-execute.json`, { version: 1 }]]);
});

test("a late file read cannot replace a newer selection or update a closed approval form", async () => {
  const changes = [];
  const view = mount("@/console/views/approvals/independent-authorization.tsx", "IndependentAuthorization", { planId, planHash, mode: "execute", onChange: value => changes.push(value) });
  const choose = value => elements(view.draw(), e => e.type === "input")[0].props.onChange({ target: { files: [value] } });
  let release;
  const delayed = { size: 1, name: "old.json", text: () => new Promise(resolve => { release = resolve; }) };
  choose(delayed); choose(file(approval)); await tick(); const count = changes.length;
  release(JSON.stringify({ ...approval, signature: "old" })); await tick();
  assert.equal(changes.length, count); assert.deepEqual(changes.at(-1), approval);
  choose(delayed); view.close(); const closedCount = changes.length;
  release(JSON.stringify(approval)); await tick(); assert.equal(changes.length, closedCount);
});

test("collector identity diagnostics use worker reports while legacy diagnostics keep their API guidance", () => {
  const identity = load("@/console/views/integrations/aws-identity.tsx");
  const base = { api: { state: "ERROR", error_code: "WORKER_IDENTITY_UNKNOWN" }, worker: null, worker_stale: true, sign_in: null };
  assert.match(identity.identityIssue({ ...base, identity_source: "collector" }, L, true).text, /collection process/);
  const unknown = { ...base, sign_in: { reason: "UNKNOWN" } };
  assert.match(identity.identityIssue(unknown, L, true).fix, /API container/);
  assert.match(identity.identityIssue({ ...unknown, identity_source: "collector" }, L, true).fix, /collection process/);
  assert.match(identity.refusalText("WORKER_IDENTITY_MISMATCH", L), /API and the worker/);
  assert.doesNotMatch(identity.refusalText("WORKER_IDENTITY_MISMATCH", L, "collector"), /API/);
});

test("key-action identity copy distinguishes the dedicated remediator from the legacy API", () => {
  for (const source of [undefined, "remediator"]) {
    const data = { identity_source: source, api: { state: "ERROR", error_code: "WORKER_IDENTITY_UNKNOWN" }, profile: null, approved: null, policy: {}, remediation_role_name: "ActionRole" };
    const view = mount("@/console/views/integrations/aws-settings.tsx", "AwsKeyActionIdentity", { regionOptions: [] }, {
      "@/console/data": { ...load("@/console/data.ts"), useSaved: () => () => {}, useApi: () => ({ data, reload() {} }) },
    });
    const copy = text(view.draw());
    assert.match(copy, source ? /dedicated remediation process/ : /run in the API/);
    if (source) { assert.doesNotMatch(copy, /API process/); assert.match(copy, /report from the remediation process/); }
  }
});

test("signature and pending read refusals explain the next step in both languages", () => {
  const { reasonText } = load("@/console/data.ts"), { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  for (const code of ["SIGNED_AUTHORIZATION_INVALID", "SIGNED_AUTHORIZATION_ALREADY_USED", "AWS_READ_PENDING"]) {
    for (const say of [L, ko => ko]) assert.doesNotMatch(reasonText(new DashboardAPIError(code, 409), say), /conflicted|충돌/);
  }
});

test("machine token checks show queued and failed results, allow retry after revision changes, and retain legacy success", async () => {
  const fixture = { configured: true, revision: 2, secret_saved: true, idp: { token_url: "https://idp.example/token", client_id: "synthetic", auth_method: "client_secret_post", token_field: "access_token" },
    aws: { enabled: true, role_arn: "arn:aws:iam::123456789012:role/synthetic" }, gcp: null, azure: null, vault: [], processes: [], test: null };
  let data = fixture; const calls = [];
  const view = mount("@/console/views/integrations/machine.tsx", "MachineIdentityModal", { onClose() {} }, {
    "@/console/data": { ...load("@/console/data.ts"), useSaved: () => () => {},
      useApi: path => path?.endsWith("/setup") ? { data: { steps: {} }, reload() {} } : { data, replace: next => { data = next; }, reload() {} },
      send: async (path, method) => { calls.push([path, method]); return { ...fixture, test: { revision: 2, state: "QUEUED", tokens: {} } }; } },
  });
  const button = label => elements(view.draw(), e => e.type === "button" && text(e) === label)[0];
  view.draw();
  button("Fetch a token now").props.onClick(); await tick();
  assert.equal(button("Checking collection process").props.disabled, true);
  assert.deepEqual(calls, [["settings/machine-identity/test", "POST"]]);
  data = { ...data, revision: 3 }; assert.equal(button("Fetch a token now").props.disabled, false);
  data = { ...data, test: { state: "FAILED", tokens: {} } }; assert.match(text(view.draw()), /Token check failed/);
  data = { ...data, test: { tokens: { aws: { state: "READY", claims: { sub: "legacy-subject" } } } } };
  assert.match(text(view.draw()), /legacy-subject/); assert.equal(button("Fetch a token now").props.disabled, false);
});
