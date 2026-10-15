// The integrations page's account / content split: which card says connected, where a connection is listed, and
// what each of its features is doing there. Synthetic descriptors shaped like the catalog; no customer data.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const sections = load("@/console/views/integrations/sections.ts");
const { accountFeatures, accountNote, accountOwner, badges, contentStartable, liveIn, runnableIn, sectionCounts, sectionsOf, sectionState, sectionView } = sections;
const plain = value => JSON.parse(JSON.stringify(value));
const ko = (k) => k, en = (_k, e) => e;
const E = "exposure", I = "inventory", V = "vault", R = "remediation";

const notion = { provider: "notion", label: "Notion", label_ko: "Notion", category: "saas",
  editions: [{ id: "standard", label: "Free / Plus / Business", label_ko: "Free / Plus / Business" }, { id: "enterprise", label: "Enterprise", label_ko: "Enterprise" },
    { id: "cloud", label: "Existing connection", label_ko: "기존 연결", new_setup: false }],
  purposes: { exposure: {}, inventory: { editions: ["enterprise", "cloud"], permissions: [{ id: "audit", label: "Audit log", label_ko: "감사 로그" }] },
    remediation: { editions: ["enterprise", "cloud"] } },
  auth_methods: [{ id: "integration", purposes: [E], auth_first: { context: [] } },
    { id: "organization_bot", purposes: [I, R], editions: ["enterprise", "cloud"], auth_first: { context: [] } }] };
const confluence = { provider: "confluence", label: "Confluence", label_ko: "Confluence", category: "saas",
  editions: [{ id: "cloud", label: "Confluence Cloud", label_ko: "Confluence Cloud" }, { id: "data_center", label: "Confluence Data Center", label_ko: "Confluence Data Center" }],
  purposes: { exposure: {} }, auth_methods: [{ id: "token", purposes: [E], auth_first: { context: [] } }] };
const aws = { provider: "aws", label: "Amazon Web Services", label_ko: "Amazon Web Services", category: "cloud", editions: [{ id: "cloud", label: "AWS", label_ko: "AWS" }],
  purposes: { exposure: {}, inventory: { types: [{ id: "keys", label: "Keys", label_ko: "키", support: "" }] }, vault: {} },
  auth_methods: [{ id: "role", purposes: [E, I, V], auth_first: { context: [] } }] };
const website = { provider: "website", label: "Websites", label_ko: "웹사이트", category: "cloud", editions: [{ id: "web", label: "Web", label_ko: "웹" }],
  purposes: { exposure: {} }, auth_methods: [{ id: "none", purposes: [E] }] };

const conn = (over) => ({ id: "c1", provider: "notion", edition: "standard", name: "Notion", status: "ACTIVE", revision: 1, purposes: [], plans: {},
  target: {}, auth_method: "integration", renewal: null, credential: { roles: [] }, children: [],
  checks: { results: {}, checked_at: null, requested_at: null, job_id: null, stale: false, error: null }, ...over });
const contentOnly = conn({ purposes: [E], plans: { exposure: {} }, feature_enabled: { exposure: true } });
const authOnly = conn({ status: "CHECKED", checks: { ...conn({}).checks, authentication_only: true } });
const awsBoth = conn({ provider: "aws", edition: "cloud", name: "AWS", auth_method: "role", purposes: [I, E], plans: { inventory: {}, exposure: {} },
  feature_enabled: { inventory: true, exposure: true } });

test("a content scan alone never makes the account card connected, nor does an authentication-only owner", () => {
  assert.equal(liveIn(contentOnly, "account"), false, "Notion standard content-only: account card not connected");
  assert.equal(liveIn(contentOnly, "exposure"), true);
  assert.equal(liveIn(authOnly, "account"), false);
  assert.equal(liveIn(authOnly, "exposure"), false);
  assert.equal(liveIn(authOnly), false, "nor is the provider counted as connected");
  assert.equal(liveIn(awsBoth, "account"), true);
  assert.equal(liveIn(awsBoth, "exposure"), true);
  assert.equal(liveIn({ ...awsBoth, feature_enabled: { inventory: false, exposure: true } }, "account"), false, "a switched-off inventory");
  assert.equal(liveIn({ ...awsBoth, status: "DISABLED" }, "exposure"), false);
  assert.equal(liveIn({ ...awsBoth, status: "CHECKED" }), false);
});

test("the account card shows the account features new setups offer, says which editions, and is hidden without any", () => {
  assert.deepEqual(plain(accountFeatures(confluence)), [], "Confluence has no account card");
  assert.deepEqual(plain(accountFeatures(notion)), [I, R]);
  assert.equal(accountNote(notion, ko), "Enterprise 전용: 발급 목록·조치");
  assert.equal(accountNote(notion, en), "Enterprise only: Inventory · Actions");
  assert.deepEqual(plain(accountFeatures(aws)), [I, V]);
  assert.equal(accountNote(aws, ko), null, "every edition offers them");
  // The edition only existing connections keep is not a new setup: alone it neither shows the card nor names itself.
  const legacyOnly = { ...notion, editions: notion.editions.map(e => e.id === "enterprise" ? { ...e, new_setup: false } : e) };
  assert.deepEqual(plain(accountFeatures(legacyOnly)), []);
  // The account chooser leaves a page-reading connection of a plan without account features out.
  assert.equal(accountOwner(contentOnly, notion), false);
  assert.equal(accountOwner({ ...contentOnly, edition: "enterprise" }, notion), true);
});

test("a connection is listed in each section it has a feature in; one without features where its edition's card is", () => {
  assert.deepEqual(plain(sectionsOf(awsBoth, aws)), ["account", "exposure"]);
  assert.deepEqual(plain(sectionsOf(contentOnly, notion)), ["exposure"]);
  assert.deepEqual(plain(sectionsOf(authOnly, notion)), ["exposure"], "standard: no account feature");
  assert.deepEqual(plain(sectionsOf({ ...authOnly, edition: "enterprise" }, notion)), ["account"]);
  assert.deepEqual(plain(sectionsOf(conn({ purposes: [], plans: { inventory: {} }, edition: "enterprise" }), notion)), ["account"], "a plan alone counts");
  assert.deepEqual(plain(sectionsOf(conn({ provider: "gone" }), undefined)), ["account"], "a record no catalog describes is still listed");
});

test("each feature reads on, off, missing (with what is missing) or pending", () => {
  const c = conn({ edition: "enterprise", purposes: [E, I, R], plans: { exposure: {} }, feature_enabled: { exposure: true },
    checks: { ...conn({}).checks, results: { inventory: { status: "MISSING", items: [{ permission: "audit", status: "MISSING" }, { permission: "other", status: "GRANTED" }] } } } });
  assert.deepEqual(plain(badges(c, "account", notion, ko)), [
    { purpose: I, state: "missing", missing: ["감사 로그"] }, { purpose: R, state: "pending", missing: [] }]);
  assert.deepEqual(plain(badges(c, "exposure", notion, ko)), [{ purpose: E, state: "on", missing: [] }]);
  assert.deepEqual(plain(badges({ ...c, feature_enabled: { exposure: false } }, "exposure", notion, ko)).map(b => b.state), ["off"]);
  assert.deepEqual(plain(badges({ ...c, status: "DISABLED" }, "exposure", notion, ko)).map(b => b.state), ["off"]);
  assert.deepEqual(plain(badges({ ...c, status: "CHECKED" }, "exposure", notion, ko)).map(b => b.state), ["pending"]);
  const errored = { ...c, checks: { ...c.checks, results: { inventory: { status: "ERROR", items: [] } } } };
  assert.equal(badges(errored, "account", notion, ko)[0].state, "missing", "any refusal holds the feature back");
  // On and held together: the account row says some features lack access, and names the permission.
  const state = sectionState({ ...c, plans: { exposure: {}, remediation: {} }, feature_enabled: { exposure: true, remediation: true } }, "account", [], ko, notion);
  assert.equal(state.label, "일부 기능 권한 부족");
  assert.match(state.note, /감사 로그/);
  assert.equal(sectionState(authOnly, "exposure", [], ko, notion).choose, true, "an authentication-only owner under content chooses locations");
  assert.equal(sectionState(authOnly, "exposure", [], en, notion).label, "Account sign-in only");
});

test("the content badge counts scoped locations, not the kinds of source a scan reads", () => {
  const d = { ...aws, purposes: { ...aws.purposes, exposure: { scans: [{ id: "objects", label: "Objects", label_ko: "객체" }] } } };
  const counts = sectionCounts(d, awsBoth, 7);
  assert.equal(counts.exposure, 7);
  assert.equal(badges(awsBoth, "exposure", d, ko, counts)[0].count, 7);
  assert.equal(sectionCounts(d, awsBoth, undefined).exposure, undefined, "nothing scoped yet");
});

test("a content card opens with an owner, or without one where a sign-in-first method reads content (not AWS)", () => {
  assert.equal(contentStartable(aws, 0), false, "S3 reads through the account's role");
  assert.equal(contentStartable(aws, 1), true);
  assert.equal(contentStartable(notion, 0), true);
  assert.equal(contentStartable(confluence, 0), true);
  assert.equal(contentStartable(website, 0), false, "no sign-in-first method");
  assert.equal(contentStartable({ ...notion, auth_methods: notion.auth_methods.map(m => ({ ...m, new_setup: false })) }, 0), false);
});

test("a remediation credential is never offered as a content owner", () => {
  const acting = conn({ provider: "github", auth_method: "github_app", purposes: [R], plans: { remediation: {} } });
  assert.equal(sections.contentOwner(acting), false);
  assert.equal(sections.contentOwner({ ...acting, checks: { ...acting.checks, authentication_only: true } }), false);
  assert.equal(sections.contentOwner({ ...acting, purposes: [I], plans: { inventory: {} } }), true);
  assert.equal(sections.contentOwner(contentOnly), true);
  assert.equal(sections.contentOwner(authOnly), true);
});

test("failed and unreported provider checks never claim access checked or healthy", () => {
  const { rowState } = load("@/console/views/integrations/model.ts");
  for (const status of ["CHECKED", "ACTIVE"]) for (const locale of [ko, en]) {
    for (const [result, error] of [["ERROR", null], ["NOT_REPORTED", null], ["GRANTED", "CREDENTIAL_UNAVAILABLE"]]) {
      const c = conn({ status, purposes: [I], plans: { inventory: {} }, checks: { ...conn({}).checks,
        checked_at: "2026-10-01T00:00:00Z", error, results: { inventory: { items: [{ permission: "audit", status: result }] } } } });
      const state = rowState(c, [], locale);
      assert.equal(state.label, locale("확인 필요", "Needs attention"));
      assert.equal(state.fix, status === "CHECKED" ? "resume" : "recheck");
      assert.doesNotMatch(state.note, /Access checked|권한을 확인했습니다/);
    }
  }
  const optional = conn({ purposes: [I], plans: { inventory: { audit_events: false } },
    checks: { ...conn({}).checks, results: { inventory: { items: [{ permission: "audit", status: "NOT_REPORTED" }] } } } });
  assert.equal(rowState(optional, [], en, undefined, { ...notion, purposes: { inventory: {
    permissions: [{ id: "audit", option: "audit_events" }] } } }).label, "Healthy", "unused optional checks stay excluded");
});

test("Collect now runs only the row's section", async () => {
  const calls = [];
  const { collectConnection } = load("@/console/views/integrations/collect.tsx", { overrides: {
    "@/console/data": { send: async (path, method, body) => {
      calls.push(path === "scan-runs" ? `run:${body.plan_id}` : path);
      return path.endsWith("/preview") ? { executable: true, plan_id: "p" } : { id: "job" };
    } },
    "@/console/views/integrations/scope": { scopeTargets: () => [{ id: "s3", name: "S3" }],
      readProfiles: async () => ({ profiles: [{ id: "profile", name: "Buckets", version: 1, selected_roots: [{}] }] }) },
  } });
  const c = { plans: { inventory: {}, exposure: {} }, feature_enabled: {}, children: [{ kind: "coverage", id: "iam", purpose: I }] };
  await collectConnection(c, undefined, [I, V]);
  assert.deepEqual(calls, ["coverage/connections/iam/collect"]);
  calls.length = 0;
  await collectConnection(c, undefined, [E]);
  assert.deepEqual(calls, ["scan-scope-profiles/profile/preview", "run:p"]);
  calls.length = 0;
  await collectConnection(c);
  assert.equal(calls.length, 3, "without a filter, everything as before");
});

test("a sign-in to renew on one section's records is the connection's problem, on every row (the fix on the first)", () => {
  const c = { ...awsBoth, children: [{ kind: "coverage", id: "iam", purpose: I }, { kind: "content", id: "s3", purpose: E }] };
  const item = (key, auth_state) => ({ key, kind: key.split(":")[0], id: key.split(":")[1], provider: "aws", name: key, auth_state, auth_reason: null,
    expires_at: null, expiry_stage: "", last_success_at: "2026-10-01T00:00:00Z", last_failure_at: null, last_failure_code: null, last_status: "COMPLETE", freshness: "" });
  const health = [item("coverage:iam", "READY"), item("content:s3", "REAUTH_REQUIRED")];
  assert.deepEqual(plain(sectionsOf(c, aws)), ["account", "exposure"]);
  for (const entry of ["account", "exposure"]) {
    const state = sectionState(c, entry, health, ko, aws);
    assert.equal(state.fix, "reauth", `${entry}: the healthy inventory does not hide the content side's renewal`);
    assert.equal(state.label, "확인 필요");
  }
  assert.equal(sections.CONNECTION_FIXES.reauth, true, "rendered once, on the first row");
});

test("an AWS account its inventory made is what S3 scans read: the content row collects and shows its run", async () => {
  // As aws onboarding makes it: the account record carries the connection's first purpose, inventory.
  const c = { ...awsBoth, children: [{ kind: "aws_account", id: "acct", purpose: I, account_id: "123456789012" }, { kind: "coverage", id: "iam", purpose: I }] };
  assert.equal(runnableIn(c, "exposure"), true, "S3 Collect now is enabled");
  assert.equal(runnableIn({ ...c, feature_enabled: { inventory: true, exposure: false } }, "exposure"), false, "not while the scan is off");
  assert.equal(runnableIn({ ...c, children: [] }, "exposure"), false, "no account, nothing to scan");
  assert.equal(runnableIn(c, "account"), true);
  assert.deepEqual(plain(sectionView(c, "exposure").children.map(child => child.id)), ["acct"], "the account's health and last run are the content row's");
  assert.deepEqual(plain(sectionView(c, "account").children.map(child => child.id)), ["acct", "iam"]);
  const calls = [];
  const { collectConnection } = load("@/console/views/integrations/collect.tsx", { overrides: {
    "@/console/data": { send: async (path, method, body) => {
      calls.push(path === "scan-runs" ? `run:${body.plan_id}` : path);
      return path.endsWith("/preview") ? { executable: true, plan_id: "p" } : { id: "job" };
    } },
    "@/console/views/integrations/scope": { scopeTargets: () => [{ kind: "aws", id: "acct", sourceType: "s3", name: "123456789012" }],
      readProfiles: async () => ({ profiles: [{ id: "buckets", name: "Buckets", version: 1, selected_roots: [{}] }] }) },
  } });
  await collectConnection(c, undefined, [E]);
  assert.deepEqual(calls, ["scan-scope-profiles/buckets/preview", "run:p"], "only the scan scope, never the inventory");
});
