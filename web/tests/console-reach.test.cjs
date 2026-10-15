"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;
// An account as GET /api/v1/aws/accounts serves it (cremore/api/aws_support.py present_aws_account).
const account = (fields) => ({ id: "a1", account_id: "123456789012", name: "prod", access: "ROLE", enabled: true, source: "MANUAL", org_blocks: [],
  scanner_role_arn: "arn:aws:iam::123456789012:role/CredentialExposureScanner", remediation_role_arn: null, sso_role_name: null,
  validation_status: "VALID", validation_detail: "SCANNER_ROLE_ASSUMED", validated_at: null,
  remediation_validation_status: "NOT_CONFIGURED", remediation_validation_detail: null, remediation_validated_at: null, ...fields });
const ROW = { busy: false, roleName: null, roleWhy: null, confirming: false, opened: false, deployment: null,
  onCheck() {}, onAddRole() {}, onPromote() {}, onCancel() {}, onDeploy() {} };

function row(props) {
  const locale = load("@/components/locale.tsx");
  const reach = load("@/console/views/integrations/reach.tsx");
  const element = React.createElement("table", null, React.createElement("tbody", null, React.createElement(reach.AwsAccountRow, { ...ROW, ...props })));
  return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" }, element));
}

// The view's own code, driven without a provider: state hooks are scripted, reads answer from fixtures, writes and
// toasts are recorded (the scan-state tests' way).
function mount(name, { api = {}, replies = {} } = {}) {
  const hooks = [], sends = [], toasts = [], reads = {};
  let cursor = 0, effects = [];
  const react = { ...React,
    useState(initial) {
      const index = cursor++;
      if (!(index in hooks)) hooks[index] = typeof initial === "function" ? initial() : initial;
      return [hooks[index], value => { hooks[index] = typeof value === "function" ? value(hooks[index]) : value; }];
    },
    useRef(value) { const index = cursor++; return hooks[index] ||= { current: value }; },
    useEffect(effect, deps) {
      const index = cursor++, before = hooks[index];
      if (!before || deps.some((value, i) => !Object.is(value, before.deps[i]))) effects.push(() => { before?.cleanup?.(); hooks[index] = { deps, cleanup: effect() }; });
    },
  };
  // A fixture that is an Error is a read that failed (or a request the API refused); its `stale` is the data an earlier
  // read left (useApi keeps it).
  const data = { ...load("@/console/data.ts"), useSaved: () => () => {},
    useApi: (path, options = {}) => {
      if (path === null) return { reload() {} };
      reads[path] = options;
      return api[path] instanceof Error ? { data: api[path].stale, error: api[path], reload() {} } : { data: api[path], error: null, reload() {} };
    },
    // Copied into this realm, so the recorded bodies compare with plain objects.
    send: async (path, method, body) => {
      sends.push([path, method, JSON.parse(JSON.stringify(body ?? null))]);
      if (replies[path] instanceof Error) throw replies[path];
      return replies[path] ?? {};
    } };
  const reach = load("@/console/views/integrations/reach.tsx", { overrides: { react, "@/console/data": data,
    "@/console/layer": { ...load("@/console/layer.tsx"), useToast: () => (text, tone) => toasts.push([text, tone]) },
    "@/console/text": { ...load("@/console/text.ts"), useL: () => L },
    "@/components/locale": { ...load("@/components/locale.tsx"), useLocale: () => "ko" } } });
  return { draw: props => { cursor = 0; effects = []; const tree = reach[name](props); effects.forEach(effect => effect()); return tree; }, sends, toasts, reads, api };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const elements = (node, match) => !node || typeof node !== "object" ? []
  : [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap(child => elements(child, match))];
const text = node => typeof node === "string" ? node : !node || typeof node !== "object" ? "" : React.Children.toArray(node.props?.children).map(text).join("");
const button = (tree, label) => elements(tree, e => e.type === "button" && text(e) === label)[0];

test("connected targets are offered where an integration reaches targets of its own", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  assert.equal(reach.reachKind({ provider: "aws", target: {}, children: [{ kind: "aws_account", id: "a1" }] }), "aws");
  assert.equal(reach.reachKind({ provider: "aws", target: {}, children: [{ kind: "metadata", id: "m1" }] }), null);
  assert.equal(reach.reachKind({ provider: "github", target: {}, children: [{ kind: "metadata", id: "m1" }] }), null);
  // One entry in the menu of an integration that is not turned off, for Admins (the account checks and changes are Admin routes).
  const page = source("@/console/views/integrations/page.tsx");
  assert.match(page, /session\.role === "Admin" && target\.status !== "DISABLED" && reachKind\(target\) \? <MenuItem icon="grid" onSelect=\{\(\) => \{ rowMenu\.close\(\); setReachFor\(target\); \}\}>\{L\("연결 대상 현황", "Connected targets"\)\}/);
  assert.match(page, /\{reachFor \? <ReachModal conn=\{reachFor\} onClose=\{\(\) => setReachFor\(null\)\} \/> : null\}/);
});

test("an account's access reads in words, with why where it is not confirmed and for which identity", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  const plain = (state) => ({ ...state });
  assert.deepEqual(plain(reach.accessText("VALID", "SCANNER_ROLE_ASSUMED", L)), { text: "확인됨", tone: "ok", why: null });
  assert.deepEqual(plain(reach.accessText("INVALID", "ASSUME_ROLE_DENIED", L)), { text: "확인 실패", tone: "bad", why: "이 계정의 역할을 맡지 못했습니다. 역할과 신뢰 정책을 확인합니다." });
  assert.match(reach.accessText("PENDING", "REVALIDATION_REQUIRED", L).why, /다시 확인해야 합니다/);
  assert.deepEqual(plain(reach.accessText("NOT_CONFIGURED", null, L)), { text: "설정 안 됨", tone: undefined, why: null });
  assert.equal(reach.accessText("SOMETHING_NEW", null, L).text, "SOMETHING_NEW");
  // A key action waits for the key-action identity, not the one scanning runs as.
  assert.match(reach.accessText("PENDING", "IDENTITY_NOT_APPROVED", L).why, /CreMore가 쓰는 AWS 신원을 먼저 승인합니다/);
  assert.match(reach.accessText("PENDING", "IDENTITY_NOT_APPROVED", L, "remediation").why, /키 조치 신원을 먼저 승인합니다/);
  // The key-action role sits in the account's own partition, under the installation's role name.
  assert.equal(reach.keyActionRoleArn(account({}), "CredentialExposureRemediationRole"), "arn:aws:iam::123456789012:role/CredentialExposureRemediationRole");
  assert.equal(reach.keyActionRoleArn(account({ scanner_role_arn: "arn:aws-cn:iam::123456789012:role/x" }), "R"), "arn:aws-cn:iam::123456789012:role/R");
  assert.equal(reach.keyActionRoleArn(account({ scanner_role_arn: null }), "R"), "arn:aws:iam::123456789012:role/R");
  assert.equal(reach.keyActionRoleArn(account({ scanner_role_arn: "arn:bogus:iam::1:role/x" }), "R"), "arn:aws:iam::123456789012:role/R");
});

test("an account CreMore does not use says so, whatever its last check said", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  assert.deepEqual([...reach.blocksOf(account({}))], []);
  assert.deepEqual([...reach.blocksOf(account({ enabled: false, org_blocks: ["ORG_ACCOUNT_REMOVED"] }))], ["ACCOUNT_DISABLED", "ORG_ACCOUNT_REMOVED"]);
  const gone = row({ account: account({ source: "ORGANIZATION", org_blocks: ["ORG_ACCOUNT_REMOVED"] }) });
  assert.match(gone, /쓰지 않음/);
  assert.doesNotMatch(gone, /확인됨/);
  assert.match(gone, /이 계정은 AWS Organizations에서 빠졌습니다/);
  assert.match(row({ account: account({ enabled: false }) }), /이 계정은 꺼져 있습니다[\s\S]*쓰지 않음/);
});

test("each account says what to do next for key actions: move to a member role, add the role, approve first, or check it", () => {
  // A permission set only scans: key actions need the account moved to a member role, asked twice.
  const sso = account({ access: "SSO_PERMISSION_SET", sso_role_name: "Audit", scanner_role_arn: null });
  assert.match(row({ account: sso }), /권한 세트로는 스캔만 합니다[\s\S]*멤버 역할로 바꾸기/);
  const asking = row({ account: sso, confirming: true });
  assert.match(asking, /확인할 때까지 이 계정을 스캔하지 않습니다\. 권한 세트 방식으로 되돌릴 수 없습니다/);
  assert.match(asking, /멤버 역할로 바꾸기[\s\S]*취소/);
  // A member role with no key-action role: add it once the key-action identity is approved, else the reason.
  assert.match(row({ account: account({}), roleName: "CredentialExposureRemediationRole" }), /키 조치 역할 추가/);
  const waiting = row({ account: account({}), roleWhy: "키 조치 신원을 먼저 승인합니다(연동 설정의 로그인 단계)." });
  assert.match(waiting, /키 조치 신원을 먼저 승인합니다/);
  assert.doesNotMatch(waiting, /키 조치 역할 추가/);
  // An Organizations StackSet account's stack is the StackSet's: no single-account role is added to it.
  const stackset = row({ account: account({ source: "ORGANIZATION", org_state: "ACTIVE" }), roleName: "R" });
  assert.match(stackset, /Organizations StackSet으로 닿는 계정에는 여기서 키 조치 역할을 더하지 않습니다/);
  assert.doesNotMatch(stackset, /키 조치 역할 추가|배포 보기/);
  // With one, its state and why, and a check.
  const set = row({ account: account({ remediation_role_arn: "arn:aws:iam::123456789012:role/CredentialExposureRemediationRole",
    remediation_validation_status: "INVALID", remediation_validation_detail: "ASSUME_ROLE_DENIED" }) });
  assert.match(set, /확인 실패[\s\S]*이 계정의 역할을 맡지 못했습니다[\s\S]*키 조치 접근 확인/);
  // CreMore's own identity reaches its account for both purposes: no role to add, nothing to deploy.
  const runtime = row({ account: account({ access: "RUNTIME_IDENTITY", scanner_role_arn: null, remediation_validation_status: "PENDING" }) });
  assert.match(runtime, /이 설치의 AWS 신원[\s\S]*키 조치 접근 확인/);
  assert.doesNotMatch(runtime, /배포 보기/);
  // Without an approved key-action identity the API refuses the check: the reason says what to do, and there is no check.
  const unapproved = row({ account: account({ access: "RUNTIME_IDENTITY", scanner_role_arn: null, remediation_validation_status: "PENDING",
    remediation_validation_detail: "IDENTITY_NOT_APPROVED" }) });
  assert.match(unapproved, /키 조치 신원을 먼저 승인합니다/);
  assert.doesNotMatch(unapproved, /키 조치 접근 확인/);
});

test("a member-role account CreMore cannot use yet shows its deployment; an update takes the CLI command", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  assert.equal(reach.deployable(account({})), false);
  assert.equal(reach.deployable(account({ validation_status: "PENDING" })), true);
  assert.equal(reach.deployable(account({ remediation_role_arn: "arn:aws:iam::1:role/R", remediation_validation_status: "PENDING" })), true);
  assert.equal(reach.deployable(account({ validation_status: "PENDING", source: "ORGANIZATION" })), false);
  assert.equal(reach.deployable(account({ access: "SSO_PERMISSION_SET", validation_status: "PENDING" })), false);
  // An account CreMore does not use is not deployed to.
  assert.equal(reach.deployable(account({ validation_status: "PENDING", enabled: false })), false);
  assert.match(row({ account: account({ validation_status: "PENDING" }) }), /배포 보기/);
  // An open deployment stays closable once the account is confirmed.
  assert.match(row({ account: account({}), opened: true }), /배포 닫기/);
  // The deployment sits under its account, across the row.
  assert.match(row({ account: account({}), deployment: React.createElement("i", null, "stack") }), /<tr class="reach-deploy"><td colSpan="3"><i>stack<\/i><\/td><\/tr>/);
  // The CloudFormation link only creates a stack: a stack already deployed is updated with the CLI command.
  const guide = source("@/console/views/integrations/guide.tsx");
  assert.match(guide, /\{cloudformation_url && !update \? <a className="ghost-btn"/);
  assert.match(guide, /CloudFormation 링크는 스택을 처음 만들 때 씁니다\. 이미 있는 스택은 CLI 명령으로 갱신합니다\./);
});

test("a scanning check stops being waited for after two minutes, even while the list cannot be read", async () => {
  const conn = { id: "p1", provider: "aws", auth_method: "role", target: {}, children: [{ kind: "aws_account", id: "a1" }] };
  const view = mount("AwsAccounts", { api: { "aws/accounts": [account({ validated_at: null })], "aws/remediation-identity": { approved: null, remediation_role_name: "R" } },
    replies: { "aws/accounts/a1/validate?purpose=scanner": { check: "QUEUED" } } });
  let tree = view.draw({ conn });
  elements(tree, e => Boolean(e.props?.account))[0].props.onCheck("scanner"); await tick();
  tree = view.draw({ conn }); tree = view.draw({ conn });
  assert.equal(view.reads["aws/accounts"].every, 5000);
  const realNow = Date.now;
  try {
    Date.now = () => realNow() + 121_000;
    const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
    // The list read before stays; only the failure is new.
    view.api["aws/accounts"] = Object.assign(new DashboardAPIError("unavailable", 503), { stale: view.api["aws/accounts"] });
    tree = view.draw({ conn }); tree = view.draw({ conn });
    assert.equal(view.reads["aws/accounts"].every, undefined);
  } finally { Date.now = realNow; }
});

test("the assume-role policy shows once its sign-in is approved, with the policy itself", () => {
  const policy = { Version: "2012-10-17", Statement: [{ Sid: "AssumeCreMoreScannerRoles", Effect: "Allow", Action: "sts:AssumeRole" }] };
  assert.equal(mount("HubPolicy", { api: { "aws/scanner-identity": { approved: null, policy } } }).draw({}), null);
  const shown = renderToStaticMarkup(mount("HubPolicy", { api: { "aws/scanner-identity": { approved: {}, policy } } }).draw({}));
  assert.match(shown, /권한 세트에 이 인라인 정책을 넣습니다[\s\S]*AssumeCreMoreScannerRoles[\s\S]*역할 맡기 정책 복사/);
  // The question to move is announced where it appears.
  assert.match(row({ account: account({ access: "SSO_PERMISSION_SET", sso_role_name: "Audit", scanner_role_arn: null }), confirming: true }),
    /<div role="status"><div class="banner warn">/);
});

test("a queued scanning check is read again until the worker has answered, and no longer", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  assert.equal(reach.answered({ a1: null }, [account({ validated_at: null })]), false);
  assert.equal(reach.answered({ a1: null }, [account({ validated_at: "2026-10-01T00:00:00Z" })]), true);
  assert.equal(reach.answered({ a1: "2026-09-30T00:00:00Z" }, [account({ validated_at: "2026-10-01T00:00:00Z" })]), true);
  // An account no longer listed is not waited for.
  assert.equal(reach.answered({ a9: null }, [account({})]), true);
});

test("the account checks and changes reach the API's own routes, for this integration's accounts only", async () => {
  const conn = { id: "p1", provider: "aws", auth_method: "sso", target: {}, children: [{ kind: "aws_account", id: "a1" }] };
  const other = account({ id: "a9", account_id: "999999999999" });
  const sso = account({ access: "SSO_PERMISSION_SET", sso_role_name: "Audit", scanner_role_arn: null });
  const view = mount("AwsAccounts", { api: { "aws/accounts": [sso, other], "aws/remediation-identity": { approved: null, remediation_role_name: "CredentialExposureRemediationRole" } },
    replies: { "aws/accounts/a1/validate?purpose=scanner": { check: "QUEUED", status: "PENDING", detail: null } } });
  let tree = view.draw({ conn });
  const rows = () => elements(tree, e => Boolean(e.props?.account));
  assert.deepEqual(rows().map(r => r.props.account.id), ["a1"]);
  // Not approved: no role to add, and why.
  assert.equal(rows()[0].props.roleName, null);
  assert.match(rows()[0].props.roleWhy, /키 조치 신원을 먼저 승인합니다/);
  // A queued scanning check says so, and the list is read again until the worker has answered.
  rows()[0].props.onCheck("scanner"); await tick();
  assert.deepEqual(view.sends.at(-1), ["aws/accounts/a1/validate?purpose=scanner", "POST", {}]);
  assert.match(view.toasts.at(-1)[0], /스캔 접근 확인을 요청했습니다/);
  tree = view.draw({ conn }); tree = view.draw({ conn });
  assert.equal(view.reads["aws/accounts"].every, 5000);
  view.api["aws/accounts"] = [{ ...sso, validation_status: "VALID", validated_at: "2026-10-01T00:00:00Z" }, other];
  tree = view.draw({ conn }); tree = view.draw({ conn });
  assert.equal(view.reads["aws/accounts"].every, undefined);
  view.api["aws/accounts"] = [sso, other];
  tree = view.draw({ conn });
  // Moving to a member role is asked twice, and Cancel leaves it as it is.
  rows()[0].props.onPromote(); tree = view.draw({ conn });
  assert.equal(rows()[0].props.confirming, true);
  rows()[0].props.onCancel(); tree = view.draw({ conn });
  assert.equal(rows()[0].props.confirming, false);
  assert.equal(view.sends.length, 1);
  rows()[0].props.onPromote(); tree = view.draw({ conn });
  rows()[0].props.onPromote(); await tick();
  assert.deepEqual(view.sends.at(-1), ["aws/accounts/a1/promote", "POST", {}]);
  // Then it is a member role with its deployment open, and the permission-set sign-in's assume-role policy shows once.
  view.api["aws/accounts"] = [{ ...sso, access: "ROLE", sso_role_name: null, scanner_role_arn: "arn:aws:iam::123456789012:role/CredentialExposureScannerRole",
    validation_status: "PENDING" }, other];
  tree = view.draw({ conn });
  assert.equal(rows()[0].props.opened, true);
  assert.equal(rows()[0].props.confirming, false);
  assert.equal(elements(tree, e => e.type?.name === "HubPolicy").length, 1);
  // The deployment closes and opens again from its row.
  rows()[0].props.onDeploy(); tree = view.draw({ conn });
  assert.equal(rows()[0].props.opened, false);
  assert.equal(elements(tree, e => e.type?.name === "HubPolicy").length, 0);
});

test("a deployment opened from this screen carries the integration's vault plan, so its first stack makes the value reader", () => {
  const vault = { value_reader: true, regions: ["us-east-1"], secret_arns: ["arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"] };
  const conn = { id: "p1", provider: "aws", auth_method: "role", target: {}, plans: { vault }, children: [{ kind: "aws_account", id: "a1" }] };
  const view = mount("AwsAccounts", { api: { "aws/accounts": [account({ validation_status: "PENDING" })],
    "aws/remediation-identity": { approved: null, remediation_role_name: "R" } } });
  let tree = view.draw({ conn });
  const first = () => elements(tree, e => Boolean(e.props?.account))[0];
  first().props.onDeploy(); tree = view.draw({ conn });
  const deployment = first().props.deployment;
  assert.equal(deployment.props.vault, vault);
  assert.equal(deployment.props.update, false);
  // An integration without a vault plan deploys as before.
  tree = view.draw({ conn: { ...conn, plans: {} } });
  assert.equal(first().props.deployment.props.vault, undefined);
});

test("a key-action role is added in the account's partition once the identity is approved, and checked by the API", async () => {
  const conn = { id: "p1", provider: "aws", auth_method: "role", target: {}, children: [{ kind: "aws_account", id: "a1" }] };
  const view = mount("AwsAccounts", { api: { "aws/accounts": [account({})], "aws/remediation-identity": { approved: {}, remediation_role_name: "CredentialExposureRemediationRole" } },
    replies: { "aws/accounts/a1/validate?purpose=remediation": { check: "COMPLETED", status: "INVALID", detail: "ASSUME_ROLE_DENIED" } } });
  let tree = view.draw({ conn });
  const first = () => elements(tree, e => Boolean(e.props?.account))[0];
  assert.equal(first().props.roleName, "CredentialExposureRemediationRole");
  first().props.onAddRole("CredentialExposureRemediationRole"); await tick(); tree = view.draw({ conn });
  assert.deepEqual(view.sends.at(-1), ["aws/accounts/a1", "PATCH", { remediation_role_arn: "arn:aws:iam::123456789012:role/CredentialExposureRemediationRole" }]);
  assert.equal(first().props.opened, true);
  // A member-role sign-in has the policy already: no assume-role policy.
  assert.equal(elements(tree, e => e.type?.name === "HubPolicy").length, 0);
  first().props.onCheck("remediation"); await tick();
  assert.equal(view.toasts.at(-1)[0], "키 조치 접근: 확인 실패 · 이 계정의 역할을 맡지 못했습니다. 역할과 신뢰 정책을 확인합니다.");
  // A key-action check refused for want of an approved identity names the key-action identity, a scanning one the
  // scanning identity; anything else reads as the API said.
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  const refused = mount("AwsAccounts", { api: { "aws/accounts": [account({ remediation_role_arn: "arn:aws:iam::123456789012:role/R" })],
    "aws/remediation-identity": { approved: {}, remediation_role_name: "R" } }, replies: {
    "aws/accounts/a1/validate?purpose=remediation": new DashboardAPIError("IDENTITY_NOT_APPROVED: approve the AWS identity first", 409),
    "aws/accounts/a1/validate?purpose=scanner": new DashboardAPIError("IDENTITY_NOT_APPROVED: approve the AWS identity first", 409) } });
  const refusedRow = elements(refused.draw({ conn }), e => Boolean(e.props?.account))[0];
  refusedRow.props.onCheck("remediation"); await tick();
  assert.deepEqual(refused.toasts.at(-1), ["키 조치 신원을 먼저 승인합니다(연동 설정의 로그인 단계).", "bad"]);
  refusedRow.props.onCheck("scanner"); await tick();
  assert.match(refused.toasts.at(-1)[0], /CreMore가 쓰는 AWS 신원을 먼저 승인합니다/);
  // Each check button sends its own purpose.
  const buttons = mount("AwsAccountRow");
  const calls = [];
  const markup = buttons.draw({ ...ROW, account: account({ remediation_role_arn: "arn:aws:iam::1:role/R" }), onCheck: purpose => calls.push(purpose) });
  button(markup, "스캔 접근 확인").props.onClick();
  button(markup, "키 조치 접근 확인").props.onClick();
  assert.deepEqual(calls, ["scanner", "remediation"]);
});

// An organization as GET .../github-organizations serves it (snapshot.organization_roster, permissions.organization_health).
const org = (name, health, fields) => ({ org: name, status: "COMPLETE", reasons: [], ...fields,
  health: { status: "permissions_present", reason: "permission_names_only_not_collection_validation", checked_at: null, repository_selection: "all", sources: [], ...health } });

test("a GitHub inventory lists its organizations: this App's installation on each and what its reads last did", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  assert.equal(reach.reachKind({ provider: "github", target: {}, children: [{ kind: "metadata", purpose: "inventory", id: "m1" }] }), "github");
  assert.equal(reach.reachKind({ provider: "github", target: {}, children: [{ kind: "content", purpose: "exposure", id: "c1" }] }), null);
  const plain = (state) => ({ ...state });
  assert.deepEqual(plain(reach.healthText(org("acme", {}).health, L, "ko")), { text: "권한 있음", tone: "ok", why: null });
  assert.deepEqual(plain(reach.healthText(org("acme", { status: "limited", sources: [{ kind: "org_fgpat", missing: ["organization_personal_access_tokens"], status: "missing_permissions" },
    { kind: "org_pat_requests", missing: ["organization_personal_access_tokens"], status: "missing_permissions" }] }).health, L, "ko")),
  { text: "권한 부족", tone: "partial", why: "없는 권한: organization_personal_access_tokens" });
  assert.equal(reach.healthText(org("acme", { status: "not_installed", reason: "absent_from_complete_app_installation_list" }).health, L, "ko").why, "App의 전체 설치 목록에 없습니다");
  // A lookup that failed is unknown, never not installed; its reason reads in words.
  const failed = reach.healthText(org("acme", { status: "unknown", reason: "ORGANIZATION_INSTALLATION_GITHUB_HTTP_404" }).health, L, "ko");
  assert.equal(failed.text, "확인 안 됨");
  assert.match(failed.why, /이 App의 설치를 찾지 못함\(404\)/);
  const table = (props) => {
    const locale = load("@/components/locale.tsx");
    return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" },
      React.createElement(reach.GitHubOrgTable, { busy: false, onCheck() {}, ...props })));
  };
  const markup = table({ ready: true, items: [org("acme", {}), org("beta", { status: "suspended", reason: "installation_suspended" }, { status: "PARTIAL", reasons: ["GITHUB_RATE_LIMITED"] })] });
  assert.match(markup, /acme[\s\S]*권한 있음[\s\S]*완료/);
  assert.match(markup, /beta[\s\S]*설치 정지됨[\s\S]*일부[\s\S]*GitHub 요청 한도/);
  assert.equal((markup.match(/설치 다시 확인/g) || []).length, 2);
  // No check before a finished collection of the current settings: the API would refuse it.
  assert.doesNotMatch(table({ ready: false, items: [org("acme", {})] }), /설치 다시 확인/);
});

test("the organization list says when it was cut short or not read in full, and a check goes to its own route", async () => {
  const child = { kind: "metadata", purpose: "inventory", id: "m1" };
  const base = "v2/coverage/connections/m1";
  const roster = (fields) => ({ run: { id: "r1", status: "COMPLETE", finished_at: null }, current_revision: true, items: [], total: 0,
    discovery: { status: "COMPLETE", reasons: [] }, ...fields });
  const draw = (fields) => {
    const view = mount("GitHubOrgs", { api: { [`${base}/github-organizations?limit=100`]: roster(fields), [`${base}/github-audit-links?limit=1`]: { counts: { events: 0, linked: 0, unmatched: 0 } } } });
    return { view, html: renderToStaticMarkup(view.draw({ child })) };
  };
  assert.match(draw({}).html, /이 수집이 읽은 조직이 없습니다\./);
  // An organization collection lists no organizations of its own (NOT_COLLECTED): a run that failed says so itself.
  const failedRun = draw({ run: { id: "r1", status: "FAILED", finished_at: null }, discovery: { status: "NOT_COLLECTED", reasons: [] } }).html;
  assert.match(failedRun, /이 수집이 읽은 조직이 없습니다 \(실패\)\./);
  assert.doesNotMatch(failedRun, /조직 목록을 다 읽지 못했습니다/);
  // An enterprise's list that stopped short says so, beside what it did read.
  const partial = draw({ discovery: { status: "PARTIAL", reasons: ["GITHUB_RATE_LIMITED"] }, items: [org("acme", {})], total: 1 }).html;
  assert.match(partial, /조직 목록을 다 읽지 못했습니다 \(일부\) · GitHub 요청 한도[\s\S]*acme/);
  assert.match(draw({ items: [org("acme", {})], total: 140 }).html, /조직 140개 중 1개를 보여 줍니다/);
  const { view } = draw({ items: [org("acme", {})], total: 1 });
  const tree = view.draw({ child });
  button(tree, "App 설치 목록 다시 확인").props.onClick(); await tick();
  assert.deepEqual(view.sends.at(-1), [`${base}/github-installation-check`, "POST", {}]);
  elements(tree, e => Boolean(e.props?.items) && Boolean(e.props?.onCheck))[0].props.onCheck("acme"); await tick();
  assert.deepEqual(view.sends.at(-1), [`${base}/github-installation-check`, "POST", { org: "acme" }]);
  assert.equal(view.toasts.at(-1)[0], "acme의 설치 확인을 요청했습니다");
  // With an enterprise, its inventory is a collection of its own: each one's organizations are listed.
  const reach = load("@/console/views/integrations/reach.tsx");
  assert.equal(reach.inventories({ provider: "github", target: {}, children: [child, { kind: "metadata", purpose: "inventory", id: "m2" },
    { kind: "metadata", purpose: "vault", id: "m3" }] }).length, 2);
});

test("a Google Cloud project inventory shows its project's changes and observed objects", () => {
  const reach = load("@/console/views/integrations/reach.tsx");
  const gcp = (target) => ({ provider: "gcp", target, children: [{ kind: "metadata", purpose: "inventory", id: "m1" }] });
  assert.equal(reach.reachKind(gcp({})), "gcp");
  assert.equal(reach.reachKind(gcp({ scope: "project", project: "p" })), "gcp");
  // An organization or folder inventory discovers projects; it has no project of its own to show.
  assert.equal(reach.reachKind(gcp({ scope: "organization", parent: "123" })), null);
  assert.equal(reach.reachKind({ provider: "gcp", target: {}, children: [] }), null);
  // One project collection serves inventory and vault, under whichever purpose was set up first.
  assert.equal(reach.reachKind({ provider: "gcp", target: {}, children: [{ kind: "metadata", purpose: "vault", id: "m1" }] }), "gcp");
  // A change in words (cremore/coverage/gcp_store.py event types), with the state it moved between.
  assert.equal(reach.gcpEventText({ id: "1", source_id: "x", event_type: "discovered", current_state: "active" }, L), "새로 발견");
  assert.equal(reach.gcpEventText({ id: "1", source_id: "x", event_type: "state_changed", previous_state: "active", current_state: "disabled" }, L), "상태 바뀜 · 활성 → 사용 중지");
  assert.equal(reach.gcpEventText({ id: "1", source_id: "x", event_type: "state_changed", previous_state: "unknown", current_state: "enabled" }, L), "상태 바뀜 · 알 수 없음 → 사용 중");
  assert.equal(reach.gcpEventText({ id: "1", source_id: "x", event_type: "no_longer_listed" }, L), "목록에서 사라짐");
  assert.equal(reach.shortName("projects/p/serviceAccounts/app@p.iam.gserviceaccount.com/keys/abc"), "app@p.iam.gserviceaccount.com/keys/abc");
  assert.equal(reach.shortName("projects/p/secrets/db"), "projects/p/secrets/db");
  const table = (props) => {
    const locale = load("@/components/locale.tsx");
    return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" }, React.createElement(reach.GcpTable, props)));
  };
  const events = table({ kind: "events", total: 120, items: [{ id: "e1", source_id: "projects/p/serviceAccounts/app/keys/k1", event_type: "state_changed",
    previous_state: "active", current_state: "disabled", observed_at: "2026-09-30T00:00:00Z" }] });
  assert.match(events, /app\/keys\/k1[\s\S]*상태 바뀜 · 활성 → 사용 중지/);
  assert.match(events, /최근 1건 · 전체 120건/);
  const objects = table({ kind: "objects", total: 1, items: [{ id: "o1", source_id: "projects/p/secrets/db", lifecycle_state: "no_longer_listed" }] });
  assert.match(objects, /마지막 관측[\s\S]*목록에서 사라짐/);
  assert.match(table({ kind: "events", total: 0, items: [] }), /아직 기록된 변경이 없습니다/);
});

test("a Google Cloud project's two lists are read once, and one that fails leaves the switch and the other in place", () => {
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  const base = "v2/coverage/connections/m1/gcp";
  const page = { project_id: "p", counts: { objects: 3, events: 2 }, page: { items: [], total: 0 } };
  const view = mount("GcpProject", { api: { [`${base}?kind=events&limit=50`]: page, [`${base}?kind=objects&limit=50`]: new DashboardAPIError("boom", 500) } });
  let tree = view.draw({ child: { kind: "metadata", purpose: "inventory", id: "m1" } });
  assert.match(renderToStaticMarkup(tree), /프로젝트 p[\s\S]*변경 이력 2건[\s\S]*관측한 항목 3개/);
  button(tree, "관측한 항목 3개").props.onClick();
  tree = view.draw({ child: { kind: "metadata", purpose: "inventory", id: "m1" } });
  assert.ok(button(tree, "변경 이력 2건"));
  assert.equal(elements(tree, e => e.type?.name === "ErrorLine").length, 1);
});

test("an account's refusals read in words", () => {
  const data = load("@/console/data.ts");
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  const say = code => data.reasonText(new DashboardAPIError(`${code}: refused`, 409), L);
  assert.match(say("ORG_ACCOUNT_GONE"), /AWS Organizations에서 빠졌거나 해지되어/);
  assert.match(say("SSO_ASSIGNMENT_GONE"), /더 이상 할당되어 있지 않아/);
  assert.match(say("NOT_AN_IDENTITY_CENTER_ACCOUNT"), /권한 세트로 닿는 계정만/);
  assert.match(say("CONNECTION_DISABLED_OR_MISSING"), /꺼져 있거나 없어졌습니다/);
});
