// The owner's approval link: the proxy that alone reaches the two public endpoints (never with the console's
// credential), the token the page takes from the link, its words for refusals, and who may ask an owner.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source: readSource } = require("./load-module.cjs");

// The route as built, with its own imports (the shared link-proxy helpers) resolved; only Next's response is stubbed.
function setup(env = { CREMORE_API_URL: "http://127.0.0.1:3302" }) {
  const calls = [];
  // The local admin token is configured, as in a local install: it must never be attached here.
  const api = load("@/app/api/owner-approval/[action]/route.ts", { overrides: { "next/server": { NextResponse: Response } }, globals: { Headers, Response,
    process: { env: { CREMORE_AUTH_MODE: "local", CREMORE_API_TOKEN: "synthetic-server-only", ...env } },
    fetch: async (url, options) => { calls.push({ url, options }); return Response.json({ state: "PENDING" }); } } });
  return { api, calls };
}
function post(action, body, headers = {}) {
  const all = Object.fromEntries(Object.entries({ host: "localhost:3301", origin: "http://localhost:3301", ...headers }).filter(([, value]) => value !== undefined));
  const value = new Request(`http://localhost:3301/api/owner-approval/${action}`, { method: "POST",
    headers: all, body, ...(body instanceof ReadableStream ? { duplex: "half" } : {}) });
  value.nextUrl = new URL(value.url);
  return [value, { params: Promise.resolve({ action }) }];
}
const TOKEN = "A".repeat(20) + "b_-" + "9".repeat(20);

test("the page's proxy forwards view and decide only, with the person's own sign-in and never the admin token", async () => {
  const { api, calls } = setup();
  // oauth2-proxy hands this route the signed-in person's bearer; it goes on as it came.
  const own = "Bearer synthetic-owner-sign-in";
  for (const action of ["view", "decide"]) {
    const response = await api.POST(...post(action, JSON.stringify({ token: TOKEN }), { authorization: own }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store"); assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  }
  assert.deepEqual(calls.map(call => String(call.url)), ["http://127.0.0.1:3302/api/v1/owner-approvals/view", "http://127.0.0.1:3302/api/v1/owner-approvals/decide"]);
  for (const call of calls) {
    assert.equal(new Headers(call.options.headers).get("authorization"), own);
    assert.equal(call.options.redirect, "error"); assert.equal(call.options.body, JSON.stringify({ token: TOKEN }));
  }
  // Without a sign-in, or with anything but a bearer, nothing credential-like goes on (and never the local token).
  for (const authorization of [undefined, "Basic a2ltOng=", "Bearer two words", `Bearer ${"x".repeat(17 * 1024)}`]) {
    await api.POST(...post("view", "{}", { authorization }));
    assert.equal(new Headers(calls.at(-1).options.headers).get("authorization"), null, String(authorization).slice(0, 20));
  }
  assert.doesNotMatch(JSON.stringify(calls.map(call => [...new Headers(call.options.headers)])), /synthetic-server-only/);
  for (const action of ["cancel", "view/extra", "..", ""]) assert.equal((await api.POST(...post(action, "{}"))).status, 404, action);
  assert.equal(calls.length, 6);
});

test("a cross-site page, a large body or a missing API reaches nothing", async () => {
  const { api, calls } = setup();
  for (const origin of [undefined, "https://attacker.example"]) assert.equal((await api.POST(...post("decide", "{}", { origin }))).status, 403);
  for (const headers of [{}, { "content-length": "2" }]) {
    let cancelled = false;
    const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(3 * 1024)); }, cancel() { cancelled = true; } });
    assert.equal((await api.POST(...post("decide", body, headers))).status, 413); assert.equal(cancelled, true);
  }
  assert.equal((await api.POST(...post("view", "{}", { "content-length": String(4 * 1024 + 1) }))).status, 413);
  assert.equal(calls.length, 0);
  // The owner's limit is its own 4 KiB, not the response link's 16 KiB: a body of exactly 4 KiB goes on, one byte more does not.
  assert.equal((await api.POST(...post("decide", "x".repeat(4 * 1024)))).status, 200);
  assert.equal((await api.POST(...post("decide", "x".repeat(4 * 1024 + 1)))).status, 413);
  assert.equal(calls.length, 1);
  assert.equal((await setup({}).api.POST(...post("view", "{}"))).status, 503);
});

const page = load("@/console/views/owner-approval.tsx");
const L = (ko, en) => en;

test("the page takes a token only when the fragment is one", () => {
  assert.equal(page.tokenOf(`#${TOKEN}`), TOKEN);
  assert.equal(page.tokenOf(TOKEN), TOKEN);
  for (const hash of ["", "#", `#${TOKEN}x`, `#${TOKEN.slice(1)}`, `#${TOKEN.slice(1)}=`, "#token=abc"]) assert.equal(page.tokenOf(hash), "", hash);
});

test("the page names each refusal, and anything else as a retry", () => {
  assert.match(page.linkErrorText("OWNER_APPROVAL_EXPIRED", L), /expired/);
  assert.match(page.linkErrorText("TEXT_CONTAINS_CREDENTIAL", L), /secret/);
  assert.match(page.linkErrorText("SOMETHING_ELSE", L), /Try again/);
});

test("a remediator asks the owner while the plan is open and not yet approved by them", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const NOW = Date.parse("2026-09-29T03:00:00Z");
  const plan = (extra = {}) => ({ id: "p", status: "PENDING_APPROVAL", action_type: "DISABLE_ACCESS_KEY", expires_at: "2026-10-01T00:00:00Z",
    requested_by: "rita", plan_hash: "a".repeat(64), readiness: { execution_gate_passed: true }, ...extra });
  const policy = { execution_enabled: true, auth_mode: "oidc", single_operator: false };
  const ask = (p, role = "Remediator") => approvals.planPermissions(p, policy, { id: "rita", role }, L, NOW).askOwner;
  assert.equal(ask(plan()), true);
  assert.equal(ask(plan({ status: "APPROVED", owner_approval: { state: "DECLINED" } })), true);
  assert.equal(ask(plan(), "Analyst"), false);
  assert.equal(ask(plan({ owner_approval: { state: "APPROVED" } })), false);
  assert.equal(ask(plan({ status: "VERIFIED" })), false);
  assert.equal(ask(plan({ expires_at: "2026-09-29T02:00:00Z" })), false);
});

test("execution waits for the owner while the installation asks for it, and only an Admin contains a public key", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const NOW = Date.parse("2026-09-29T03:00:00Z");
  const plan = (extra = {}) => ({ id: "p", status: "APPROVED", action_type: "DISABLE_ACCESS_KEY", expires_at: "2026-10-01T00:00:00Z",
    requested_by: "rita", approved_by: "adam", plan_hash: "a".repeat(64), readiness: { execution_gate_passed: true }, ...extra });
  const policy = { execution_enabled: true, auth_mode: "oidc", single_operator: false, owner_approval_required: true };
  const may = (p, role = "Remediator", pol = policy) => approvals.planPermissions(p, pol, { id: "carl", role }, L, NOW);
  assert.equal(may(plan()).execute, false);
  assert.match(may(plan()).why, /owner approves/);
  assert.equal(may(plan({ owner_approval: { state: "APPROVED" } })).execute, true);
  assert.equal(may(plan({ owner_approval: { state: "DECLINED" } })).execute, false);
  assert.equal(may(plan(), "Remediator", { ...policy, owner_approval_required: false }).execute, true);
  assert.equal(may(plan({ action_type: "PREPARE_ACCESS_KEY_ROTATION", rotation: { secret_arn: "arn:x", expected_current_version: "v".repeat(32) } }),
    "Remediator", { ...policy, rotation_execution_enabled: true, supported_actions: ["PREPARE_ACCESS_KEY_ROTATION"], rotation_secret_arns: ["arn:x"] }).execute, true);
  // Containment at once: an Admin, a publicly exposed key, the owner's approval still missing.
  assert.equal(may(plan({ emergency_eligible: true }), "Admin").emergency, true);
  assert.equal(may(plan({ emergency_eligible: true }), "Remediator").emergency, false);
  assert.equal(may(plan({ emergency_eligible: false }), "Admin").emergency, false);
  assert.equal(may(plan({ emergency_eligible: true, owner_approval: { state: "APPROVED" } }), "Admin").emergency, false);
  assert.equal(may(plan({ status: "VERIFIED", owner_emergency: { notice_pending: true } })).notice, true);
  assert.equal(may(plan({ status: "VERIFIED", owner_emergency: { notice_pending: false } })).notice, false);
  // Whoever decided as the owner through a link does not approve the plan; the local operator's record names nobody.
  const pending = extra => plan({ status: "PENDING_APPROVAL", approved_by: undefined, ...extra });
  const admin = (p, id) => approvals.planPermissions(p, policy, { id, role: "Admin" }, L, NOW);
  assert.equal(admin(pending({ owner_approval: { state: "APPROVED", channel: "mail", decided_by: "adam" } }), "adam").approve, false);
  assert.match(admin(pending({ owner_approval: { state: "APPROVED", channel: "mail", decided_by: "adam" } }), "adam").why, /decided as the key's owner/);
  assert.equal(admin(pending({ owner_approval: { state: "APPROVED", channel: "mail", decided_by: "kim" } }), "adam").approve, true);
  const local = { ...policy, auth_mode: "local", single_operator: true };
  assert.equal(approvals.planPermissions(pending({ owner_approval: { state: "APPROVED", channel: "record", decided_by: "local" } }), local,
    { id: "local", role: "Admin" }, L, NOW).approve, true);
});

test("a provider plan runs on its own target, and revoking waits for the deletion switch like an AWS delete", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const NOW = Date.parse("2026-09-30T03:00:00Z");
  const plan = (extra = {}) => ({ id: "p", status: "APPROVED", action_type: "DISABLE_PROVIDER_CREDENTIAL", expires_at: "2026-10-01T00:00:00Z",
    requested_by: "rita", approved_by: "adam", plan_hash: "a".repeat(64), readiness: { execution_gate_passed: true },
    target: { kind: "provider_credential", provider: "gcp", hint: "5c5c5c5c5c5c · deploy@acme.iam.gserviceaccount.com" }, ...extra });
  // The installation's list names AWS actions only; a provider plan is supported by its own target.
  const policy = { execution_enabled: true, auth_mode: "oidc", single_operator: false, supported_actions: ["DISABLE_ACCESS_KEY"] };
  const may = (p, pol = policy) => approvals.planPermissions(p, pol, { id: "carl", role: "Remediator" }, L, NOW);
  assert.equal(may(plan()).execute, true);
  assert.equal(may(plan({ action_type: "REVOKE_PROVIDER_CREDENTIAL" })).execute, false);
  assert.equal(may(plan({ action_type: "REVOKE_PROVIDER_CREDENTIAL" }), { ...policy, deletion_execution_enabled: true }).execute, true);
  assert.equal(may(plan({ status: "QUEUED" })).cancel, true);
  assert.equal(may(plan({ status: "QUEUED", provider_write_started_at: "2026-09-30T02:59:00Z" })).cancel, false);
  // An AWS-shaped plan carrying a provider action is not something this screen runs.
  assert.equal(may(plan({ target: undefined })).execute, false);
  assert.equal(approvals.isIrreversible("REVOKE_PROVIDER_CREDENTIAL") && approvals.isIrreversible("DELETE_ACCESS_KEY"), true);
  assert.equal(approvals.OWNER_ACTIONS.includes("REVOKE_PROVIDER_CREDENTIAL"), true);
  // Revoking needs the acknowledgement a deletion needs.
  const review = { ...approvals.blankReview(Date.parse("2026-09-30T00:00:00Z")), scope_evidence_id: "00000000-0000-4000-8000-000000000001",
    recovery_evidence_id: "00000000-0000-4000-8000-000000000002" };
  assert.match(approvals.reviewBody({ ...review, consumers: [] }, "REVOKE_PROVIDER_CREDENTIAL", L).problem, /cannot be undone/);
});

test("a revoke that ends an organization's grant says so, wherever the plan is named", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  // A GitHub fine-grained token keeps working elsewhere: its organization access is what goes.
  assert.equal(L(...approvals.actionWords("REVOKE_PROVIDER_CREDENTIAL", "ORGANIZATION_ACCESS")), "Revoke its organization access");
  assert.equal(approvals.actionWords("REVOKE_PROVIDER_CREDENTIAL", "ORGANIZATION_ACCESS")[0], "조직 접근 회수");
  assert.equal(L(...approvals.actionWords("REVOKE_PROVIDER_CREDENTIAL")), "Revoke the credential for good");
  assert.equal(approvals.actionWords("DISABLE_ACCESS_KEY", "ORGANIZATION_ACCESS"), approvals.ACTION_WORDS.DISABLE_ACCESS_KEY);
  // A grant already gone is the organization's grant, not the token.
  const gone = (revokes) => ({ safe_error_code: "CREDENTIAL_ABSENT", target: { kind: "provider_credential", revokes } });
  assert.equal(L(...approvals.resultCodeWords(gone("ORGANIZATION_ACCESS"))), "The grant this plan names no longer exists, so nothing was changed");
  assert.equal(approvals.resultCodeWords(gone(undefined)), approvals.RESULT_CODE_WORDS.CREDENTIAL_ABSENT);
  assert.equal(approvals.resultCodeWords({ safe_error_code: "SOMETHING_ELSE" }), undefined);
  const plans = readSource("@/console/views/approvals/plans.tsx"), queue = readSource("@/console/views/approvals/page.tsx");
  // Every place that names a plan's action goes through it.
  assert.doesNotMatch(plans + queue, /ACTION_WORDS\[plan\.action_type\]/);
});

test("the credential that acts on approved plans is its own integration", () => {
  const integrations = load("@/console/views/integrations/model.ts");
  const d = { provider: "gitlab", editions: [{ id: "cloud" }], purposes: { inventory: {}, remediation: {} },
    auth_methods: [{ id: "token", purposes: ["inventory", "remediation"], renewal: "ROTATES" }] };
  assert.equal(integrations.combinable(d, [], "remediation", "cloud"), true);
  assert.equal(integrations.combinable(d, ["inventory"], "remediation", "cloud"), false);
  assert.equal(integrations.combinable(d, ["remediation"], "inventory", "cloud"), false);
  assert.equal(integrations.PURPOSE_ORDER.at(-1), "remediation");
});
test("an approver sees every identifier a provider plan binds, never the internal key or listing", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const plan = { target: { kind: "provider_credential", provider: "gitlab", reference: {
    family: "group_access_token", token_id: 202, instance: "https://gitlab.com", scope: { kind: "group", id: 20 },
    listed_in: { kind: "group", id: "10" }, key: { namespace: "resource_access_token" }, hint: "x" } } };
  const text = approvals.referenceText(plan);
  assert.equal(text, "family group_access_token · token_id 202 · instance https://gitlab.com · scope group 20");
  assert.doesNotMatch(text, /listed_in|namespace|hint/);
});