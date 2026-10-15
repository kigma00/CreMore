// A check's outcome per feature and target: only what the catalog requires and the draft answered, never a guess.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const { featureOutcomes } = load("@/console/views/integrations/outcomes.ts");
const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
const plain = value => JSON.parse(JSON.stringify(value));
const labelled = (label, label_ko = label) => ({ label, label_ko });

const d = { provider: "azure", ...labelled("Microsoft"), editions: [{ id: "cloud", ...labelled("Cloud") }], target: [], auth_methods: [],
  purposes: {
    exposure: { permissions: [{ id: "blob_read", ...labelled("Blob read"), when: { storage_account: ["*"] } }, { id: "code_read", ...labelled("Code read") }] },
    inventory: { permissions: [{ id: "graph_read", ...labelled("Graph read") }, { id: "keys", ...labelled("Storage keys"), option: "keys" },
      { id: "sign_ins", ...labelled("Sign-in logs"), required: false }] },
  } };
const roots = { exposure: [{ id: "a", target: { storage_account: "a" } }, { id: "b", target: { storage_account: "b" } }], inventory: [{ id: "t", target: {} }] };
const outcomes = (results, blockers, purposes = ["exposure", "inventory"], targets = roots) =>
  plain(featureOutcomes(d, "workload_identity", purposes, p => targets[p] ?? [], () => ({}), results, blockers));
const granted = (permission, target_id) => ({ permission, status: "GRANTED", ...(target_id ? { target_id } : {}) });

test("every required permission granted for every selected target is ready; options off and optional ones do not hold it", () => {
  const results = { exposure: { status: "PASSED", items: ["a", "b"].flatMap(t => [granted("blob_read", t), granted("code_read", t)]) },
    inventory: { status: "PASSED", items: [granted("graph_read")] } };
  assert.deepEqual(outcomes(results, []), [
    { purpose: "exposure", ok: true, missing: [], passing: ["a", "b"] },
    { purpose: "inventory", ok: true, missing: [], passing: ["t"] },
  ]);
});

test("a feature lacking one permission is held with the server's own reason while the other stays ready", () => {
  const results = { exposure: { status: "PASSED", items: ["a", "b"].flatMap(t => [granted("blob_read", t), granted("code_read", t)]) },
    inventory: { status: "MISSING", items: [{ permission: "graph_read", status: "MISSING", detail: "HTTP_403" }] } };
  const blockers = [{ purpose: "inventory", permission: "graph_read", status: "MISSING", detail: "HTTP_403" }];
  const [exposure, inventory] = outcomes(results, blockers);
  assert.equal(exposure.ok, true);
  assert.deepEqual(inventory, { purpose: "inventory", ok: false, missing: [{ permission: "graph_read", status: "MISSING", detail: "HTTP_403" }], passing: [] });
  // Without a server blocker (a check that answered nothing for it), the unanswered permission is still missing.
  const [, unanswered] = outcomes({ ...results, inventory: { status: "NOT_REPORTED", items: [] } }, []);
  assert.deepEqual(unanswered.missing, [{ permission: "graph_read", status: "NOT_REPORTED", detail: "NOT_CHECKED", target_id: "t" }]);
});

test("a refusal on one target holds the feature but names the targets that passed", () => {
  const results = { exposure: { status: "MISSING", items: [granted("blob_read", "a"), granted("code_read", "a"),
    { permission: "blob_read", status: "MISSING", target_id: "b", detail: "HTTP_403" }, granted("code_read", "b")] } };
  const blockers = [{ purpose: "exposure", permission: "blob_read", status: "MISSING", target_id: "b", detail: "HTTP_403" }];
  assert.deepEqual(outcomes(results, blockers, ["exposure"]), [{ purpose: "exposure", ok: false,
    missing: [{ permission: "blob_read", status: "MISSING", detail: "HTTP_403", target_id: "b" }], passing: ["a"] }]);
});

test("a subject the check did not answer holds the feature and cannot be pinned on one of several targets", () => {
  const results = { exposure: { status: "PASSED", items: ["a", "b"].flatMap(t => [granted("blob_read", t), granted("code_read", t)]) } };
  const blockers = [{ purpose: "exposure", permission: "blob_read", subject: "vault-2", status: "NOT_REPORTED", detail: "NOT_CHECKED" }];
  assert.deepEqual(outcomes(results, blockers, ["exposure"]), [{ purpose: "exposure", ok: false,
    missing: [{ permission: "blob_read", status: "NOT_REPORTED", detail: "NOT_CHECKED", subject: "vault-2" }], passing: [] }]);
});

test("stale evidence leaves no feature ready, whatever the old answers said", () => {
  const results = { exposure: { status: "PASSED", items: ["a", "b"].flatMap(t => [granted("blob_read", t), granted("code_read", t)]) },
    inventory: { status: "PASSED", items: [granted("graph_read")] } };
  const stale = [{ status: "NOT_REPORTED", detail: "PERMISSION_CHECK_REQUIRED" }];
  assert.deepEqual(outcomes(results, stale).map(o => [o.purpose, o.ok, o.missing, o.passing]), [
    ["exposure", false, [{ status: "NOT_REPORTED", detail: "PERMISSION_CHECK_REQUIRED" }], []],
    ["inventory", false, [{ status: "NOT_REPORTED", detail: "PERMISSION_CHECK_REQUIRED" }], []],
  ]);
});

test("a feature with no selected target is never ready", () => {
  assert.deepEqual(outcomes({}, [], ["inventory"], {}), [{ purpose: "inventory", ok: false,
    missing: [{ status: "MISSING", detail: "ONBOARDING_EACH_FEATURE_NEEDS_TARGET" }], passing: [] }]);
});

test("the GitHub App start's refusals read as their own words in the auth-first banner, not as a generic status", () => {
  const { reasonText } = load("@/console/views/integrations/auth-first.tsx", { extraExports: "\nexport { reasonText };" });
  const ko = (k) => k, en = (_k, e) => e;
  for (const [code, status, words] of [
    ["GITHUB_APP_STORAGE_UNAVAILABLE", 409, [/저장하지 못해 GitHub로 이동하지 않았습니다/, /could not store the setup's progress/]],
    ["GITHUB_APP_RESPONSE_INVALID", 502, [/App 만들기 페이지가 아니어서/, /not this organization's new App page/]],
    ["GITHUB_APP_SIGN_IN_EXPIRED", 401, [/^CreMore 로그인이 만료됐습니다\. 다시 로그인한 뒤 다시 시작하세요\.$/, /^Your CreMore sign-in expired\. Sign in again, then start again\.$/]],
  ]) {
    const error = new DashboardAPIError(code, status);
    assert.match(reasonText(error, ko), words[0], code);
    assert.match(reasonText(error, en), words[1], code);
  }
});
