"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;
const org = (fields) => ({ enabled: false, installation_allows: true, effective: false, interval_minutes: 60, external_id: null,
  external_id_locked: false, ou_ids: [], ou_ids_locked: false, excludes: [], excludes_locked: false, auto_validate: false,
  control_tower_enabled: false, control_tower_region: "", lifecycle_queue_url: "", lifecycle_queue_acknowledged: false,
  updated_by: null, updated_at: null, ...fields });
const form = (fields) => ({ external_id: "", ou_ids: "", excludes: "", auto_validate: false, control_tower_enabled: false,
  control_tower_region: "", lifecycle_queue_url: "", lifecycle_queue_acknowledged: false, ...fields });
const plain = (value) => JSON.parse(JSON.stringify(value));

test("an Organizations save sends only what changed and never a field the installation pins", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  const external = "cremore-org-" + "shared-2026";
  assert.deepEqual(plain(aws.orgChanges(org({}), form({}))), {});
  assert.deepEqual(plain(aws.orgChanges(org({}), form({ external_id: ` ${external} `, ou_ids: "ou-abcd-11111111, r-abcd", auto_validate: true }))),
    { external_id: external, ou_ids: ["ou-abcd-11111111", "r-abcd"], auto_validate: true });
  // The same set in another order or spacing is no change.
  assert.deepEqual(plain(aws.orgChanges(org({ ou_ids: ["ou-abcd-11111111", "r-abcd"] }), form({ ou_ids: "r-abcd\nou-abcd-11111111" }))), {});
  // A pinned field is left out whatever the form says: the API refuses a pinned field that is present at all.
  const pinned = org({ external_id: "pinned-value-0123456789", external_id_locked: true, ou_ids: ["ou-abcd-11111111"], ou_ids_locked: true, excludes_locked: true });
  assert.deepEqual(plain(aws.orgChanges(pinned, form({ external_id: "other", ou_ids: "", excludes: "111111111111", auto_validate: true }))), { auto_validate: true });
});

test("the Organizations form reads the ExternalId as the role template does, and OUs, accounts and the Region as AWS does", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  assert.equal(aws.orgProblem(org({}), form({}), L), null);
  assert.equal(aws.orgProblem(org({}), form({ external_id: "cremore-org-shared-2026" }), L), null);
  // The random value the form offers is one the role template takes, and a new one each time.
  const made = aws.randomExternalId();
  assert.match(made, /^cremore-[0-9a-f]{32}$/);
  assert.match(made, aws.TEMPLATE_EXTERNAL_ID);
  assert.notEqual(made, aws.randomExternalId());
  assert.match(aws.orgProblem(org({}), form({ external_id: "too-short" }), L), /16~128자/);
  assert.equal(aws.orgProblem(org({ external_id_locked: true }), form({ external_id: "too-short" }), L), null);  // pinned: not the form's
  assert.match(aws.orgProblem(org({}), form({ ou_ids: "ou-abcd-11111111, 1234" }), L), /OU/);
  assert.match(aws.orgProblem(org({}), form({ excludes: "12345" }), L), /12자리/);
  assert.match(aws.orgProblem(org({}), form({ control_tower_enabled: true, control_tower_region: "seoul" }), L), /홈 리전/);
  assert.equal(aws.orgProblem(org({}), form({ control_tower_enabled: true, control_tower_region: "ap-northeast-2" }), L), null);
  assert.deepEqual([...aws.words(" a, b\n c ,,")], ["a", "b", "c"]);
  assert.ok(aws.ORGANIZATION_ID.test("o-abcd123456") && !aws.ORGANIZATION_ID.test("o-ab") && !aws.ORGANIZATION_ID.test("r-abcd"));
  // A saved ExternalId the template would refuse is not the form's to refuse (roles deployed with it trust exactly it);
  // a new one is. Other fields still save.
  const short = org({ external_id: "short-ext-id" });
  assert.equal(aws.orgProblem(short, form({ external_id: "short-ext-id", ou_ids: "ou-abcd-11111111", auto_validate: true }), L), null);
  assert.match(aws.orgProblem(short, form({ external_id: "other-short" }), L), /16~128자/);
  // Control Tower as the API reads it: a Region is a Region name even while off, and the lifecycle queue lives in it.
  assert.match(aws.orgProblem(org({}), form({ control_tower_region: "seoul" }), L), /홈 리전/);
  const queue = (region, suffix = "") => `https://sqs.${region}.amazonaws.com${suffix}/111111111111/` + "cremore-lifecycle";
  const ct = (region, url) => form({ control_tower_enabled: true, control_tower_region: region, lifecycle_queue_url: url });
  assert.equal(aws.orgProblem(org({}), ct("ap-northeast-2", queue("ap-northeast-2")), L), null);
  assert.match(aws.orgProblem(org({}), ct("us-east-1", queue("ap-northeast-2")), L), /수명주기 큐/);
  assert.equal(aws.orgProblem(org({}), ct("cn-north-1", queue("cn-north-1", ".cn")), L), null);
  assert.match(aws.orgProblem(org({}), ct("ap-northeast-2", "not a url"), L), /수명주기 큐/);
});

test("the automatic inventory saves all its fields in their shapes and refuses what the API would", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  const base = { enabled: true, interval: "60", all: true, accounts: ["111111111111"], cloudtrail: true, source: "event_history", window: "30",
    regions: "ap-northeast-2, us-east-1", bucket: "trail", prefixes: "AWSLogs/\n" };
  // "All accounts" sends none; Event History sends no bucket or prefix.
  assert.deepEqual(plain(aws.inventoryBody(base)), { enabled: true, interval_minutes: 60, account_ids: [], cloudtrail_enabled: true,
    cloudtrail_source: "event_history", window_days: 30, regions: ["ap-northeast-2", "us-east-1"], trail_bucket: "", trail_prefixes: [] });
  assert.deepEqual(plain(aws.inventoryBody({ ...base, all: false, source: "s3" })).trail_prefixes, ["AWSLogs/"]);
  assert.deepEqual(plain(aws.inventoryBody({ ...base, all: false, source: "s3" })).account_ids, ["111111111111"]);
  assert.equal(aws.inventoryProblem(base, L), null);
  for (const [change, words] of [[{ interval: "4" }, /5분부터/], [{ all: false, accounts: [] }, /하나 이상/], [{ window: "91" }, /1일부터 90일/],
    [{ source: "s3", window: "3651" }, /3,650일/], [{ regions: "" }, /리전/], [{ regions: "seoul" }, /리전/], [{ source: "s3", bucket: "" }, /버킷/]]) {
    assert.match(aws.inventoryProblem({ ...base, ...change }, L), words, JSON.stringify(change));
  }
  assert.equal(aws.inventoryProblem({ ...base, cloudtrail: false, regions: "" }, L), null);  // without CloudTrail no Region is needed
  // CloudTrail off hides its fields: they are left out and keep what was saved (the S3 bucket and prefixes too).
  const off = { ...base, cloudtrail: false, source: "s3", window: "999" };
  assert.deepEqual(plain(aws.inventoryBody(off)), { enabled: true, interval_minutes: 60, account_ids: [], cloudtrail_enabled: false });
  // A saved setting that cannot be read is rewritten whole, so the hidden fields are sent and checked.
  assert.equal(aws.inventoryProblem({ ...base, cloudtrail: false, window: "999" }, L), null);
  assert.match(aws.inventoryProblem({ ...base, cloudtrail: false, window: "999" }, L, true), /1일부터 90일/);
  const whole = plain(aws.inventoryBody({ ...off, window: "30" }, true));
  assert.equal(whole.trail_bucket, "trail");
  assert.deepEqual(whole.trail_prefixes, ["AWSLogs/"]);
  assert.equal(whole.cloudtrail_enabled, false);
});

test("the wizard shows AWS's parts with the feature and sign-in they belong to, for an Admin", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  const parts = (method, purposes, admin = true, provider = "aws") =>
    Object.entries(plain(aws.awsParts(provider, admin, method, purposes))).filter(([, on]) => on).map(([name]) => name);
  // The inventory's schedule comes with that feature; the investigations of discovered credentials with any feature.
  assert.deepEqual(parts("role", ["inventory", "exposure"]), ["inventory", "investigations", "organization", "keyActions"]);
  assert.deepEqual(parts("role", ["exposure"]), ["investigations", "organization", "keyActions"]);
  // How the other accounts come in follows the method: Organizations with the member role, assignments with SSO.
  assert.deepEqual(parts("sso", ["vault"]), ["investigations", "assigned", "keyActions"]);
  assert.deepEqual(parts("runtime", ["inventory"]), ["inventory", "investigations", "keyActions"]);
  // The installation's settings are an Admin's; the CreMore CLI in the customer's environment runs on its own.
  assert.deepEqual(parts("role", ["inventory"], false), []);
  assert.deepEqual(parts("customer_cli", ["inventory", "vault"]), []);
  assert.deepEqual(parts("role", ["inventory"], true, "gcp"), []);
});

test("an import that could not start and a probe that failed read as what happened", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  const none = { registered: [], changed: [], skipped: 0, adopted: 0 };
  assert.deepEqual([...aws.sweepText({ ...none, error: "no_permission_set" }, L)], ["권한 세트를 먼저 저장합니다.", "bad"]);
  assert.deepEqual([...aws.sweepText({ ...none, error: "no_external_id" }, L)], ["StackSet의 공유 ExternalId를 먼저 저장합니다.", "bad"]);
  assert.equal(aws.sweepText({ ...none, error: "bad_permission_set" }, L)[0].startsWith("저장된 권한 세트 이름이"), true);
  assert.equal(aws.sweepText({ ...none, error: "something_new" }, L)[1], "bad");
  assert.deepEqual([...aws.sweepText({ ...none, error: null, registered: [1, 2], adopted: 1 }, L)], ["등록 2 · 갱신 0 · 건너뜀 0 · 연동에 추가 1", undefined]);
  assert.equal(aws.probeText({ available: false, reason: "NOT_AN_IDENTITY_CENTER_IDENTITY: the sign-in", total: 0 }, L),
    "CreMore가 IAM Identity Center 권한 세트로 로그인해 있지 않습니다.");
  assert.equal(aws.probeText({ available: false, reason: null, total: 0, text: "서버에 연결하지 못했습니다." }, L), "서버에 연결하지 못했습니다.");
  assert.match(aws.probeText({ available: false, reason: "SOMETHING_NEW", total: 0 }, L), /SOMETHING_NEW/);
});

test("an installation lock without a code of its own, and a code an answer carries, read in words", () => {
  const data = load("@/console/data.ts");
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  assert.equal(data.reasonText(new DashboardAPIError("SCAN_SCHEDULES_MODE=disabled locks automatic inventory off", 409), L),
    "이 설치는 설정(SCAN_SCHEDULES_MODE)에서 이 기능을 꺼 두었습니다.");
  assert.equal(data.reasonText(new DashboardAPIError("AWS_REGION_INVALID: AWS_REGION is not an AWS Region name", 409), L),
    "설치 설정 AWS_REGION이 AWS 리전 이름이 아닙니다.");
  assert.equal(data.codeText("PERMISSION_SET_NOT_CHOSEN", L), "권한 세트를 먼저 저장합니다.");
  assert.equal(data.codeText("NOT_A_CODE", L), null);
  assert.equal(data.codeText(null, L), null);
});

test("each investigation names the configuration value that locks it, and the screen reaches the APIs that own them", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  assert.deepEqual(plain(Object.fromEntries(aws.INVESTIGATIONS.map(item => [item.key, item.env]))),
    { usage_lookup: "AWS_USAGE_LOOKUP_MODE", potential_access: "IAM_POTENTIAL_ACCESS_MODE", secrets_inventory: "AWS_SECRETS_INVENTORY_MODE" });
  const screen = source("@/console/views/integrations/aws-settings.tsx");
  for (const path of ["settings/aws-organizations", "settings/aws-identity-center", "settings/aws-credential-inventory", "settings/aws-investigations",
    "aws/remediation-identity", "aws/accounts/discover?source=org", "aws/accounts/discover?source=sso", "aws/accounts/discoverable?source=org",
    "aws/accounts/discoverable?source=sso"]) assert.ok(screen.includes(`"${path}"`), path);
  assert.match(screen, /api<OrgDeployment>\(`aws\/onboarding\/organization\?organization_id=\$\{encodeURIComponent\(orgId\.trim\(\)\)\}`\)/);
  // AWS is one provider: no menu of its own. What to collect shows the inventory's schedule and each feature's
  // investigations; the sign-in's setup steps hold the account discovery and the key action identity.
  assert.doesNotMatch(source("@/console/views/integrations/page.tsx"), /aws-settings|AWS 설정/);
  // The wizard keeps the parts mounted and shows each by awsParts, on its own step.
  const wizard = source("@/console/views/integrations/wizard.tsx");
  assert.match(wizard, /const aws = awsParts\(d\.provider, admin, method\?\.id, purposes\);/);
  assert.match(wizard, /<div hidden=\{step !== 1\}>\s*<div className="ig-section" hidden=\{!aws\.inventory\}>[\s\S]*?<AwsInventory regionOptions=\{regionOptions\} \/>/);
  assert.match(wizard, /hidden=\{!aws\.investigations\}>[\s\S]*?<AwsInvestigations keys=\{investigationKeys\(purposes\)\} \/>/);
  assert.match(wizard, /<div hidden=\{step !== 2\}>\s*<div className="ig-section" hidden=\{!aws\.organization\}>[\s\S]*?<AwsOrganizations regionOptions=\{regionOptions\} \/>[\s\S]*?hidden=\{!aws\.assigned\}>[\s\S]*?<AwsIdentityCenter \/>[\s\S]*?hidden=\{!aws\.keyActions\}>[\s\S]*?<AwsKeyActionIdentity regionOptions=\{regionOptions\} \/>/);
  assert.match(wizard, /\{body\}\s*\{awsTail\}/);
  // A <details> heading inside a dialog takes part in the focus trap.
  assert.match(source("@/console/layer.tsx"), /const FOCUSABLE = "[^"]*\bsummary\b/);
  // Approving the key action identity again replaces the approval, so it asks first; a new approval does not.
  assert.match(screen, /onClick=\{\(\) => \{ if \(v\.approved\) setConfirming\(true\); else void approve\(\); \}\}/);
  // The commands are made from what is saved: an unsaved ExternalId, OU or exclusion blocks them, with the reason shown.
  assert.match(screen, /\["external_id", "ou_ids", "excludes"\]\.some\(name => name in changes\)/);
  assert.match(screen, /disabled=\{Boolean\(working\) \|\| Boolean\(deployBlock\) \|\| !orgIdOk\}/);
});


test("investigation choices follow selected features and hidden edits never leave the wizard", () => {
  const aws = load("@/console/views/integrations/aws-settings.tsx");
  assert.deepEqual(plain(aws.investigationKeys(["inventory"])), ["usage_lookup", "potential_access"]);
  assert.deepEqual(plain(aws.investigationKeys(["exposure"])), ["usage_lookup", "potential_access"]);
  assert.deepEqual(plain(aws.investigationKeys(["vault"])), ["secrets_inventory"]);
  const edits = { usage_lookup: { enabled: true, expected: false }, secrets_inventory: { enabled: true, expected: false } };
  assert.deepEqual(plain(aws.investigationRequest(edits, ["inventory"])), {
    changes: { usage_lookup: true }, expected: { usage_lookup: false },
  });
  assert.deepEqual(plain(aws.investigationRequest(edits, ["vault"])), {
    changes: { secrets_inventory: true }, expected: { secrets_inventory: false },
  });
  assert.equal(aws.investigationRequest(edits, []), undefined);
});
