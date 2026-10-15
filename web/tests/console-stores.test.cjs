"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;
const ARN = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:prod/app-key-AbCdEf";

// A view's own code, driven without a provider: hooks are scripted, reads answer from fixtures (an Error is a read
// that failed), writes, reloads and toasts are recorded (console-reach.test.cjs's way). A part the module keeps to
// itself is reached by exporting it for the test.
const INTERNAL = { Rotation: "store", CollectorToken: "store", Metadata: "binding" };
function mount(file, name, { api = {}, replies = {} } = {}) {
  const hooks = [], sends = [], toasts = [], reloads = [];
  let cursor = 0, effects = [], revisions = 0;
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
  const data = { ...load("@/console/data.ts"), useSaved: () => () => { revisions += 1; },
    useApi: path => {
      if (path === null) return { reload() {} };
      const answer = api[path];
      return { data: answer instanceof Error ? undefined : answer, error: answer instanceof Error ? answer : null,
        reload() { reloads.push(path); }, replace(value) { api[path] = value; } };
    },
    send: async (path, method, body) => {
      sends.push([path, method, JSON.parse(JSON.stringify(body ?? null))]);
      if (replies[path] instanceof Error) throw replies[path];
      return replies[path] ?? {};
    } };
  const module = load(file, { extraExports: INTERNAL[name] ? `
export { ${name} };` : "", overrides: { react, "@/console/data": data,
    "@/console/layer": { ...load("@/console/layer.tsx"), useToast: () => (text, tone) => toasts.push([text, tone]) },
    "@/console/text": { ...load("@/console/text.ts"), useL: () => L },
    "@/components/locale": { ...load("@/components/locale.tsx"), useLocale: () => "ko" },
    "@/lib/dashboard-api": { ...load("@/lib/dashboard-api.ts"), api: async path => api[path] } } });
  return { draw: props => { cursor = 0; effects = []; const tree = module[name](props); effects.forEach(effect => effect()); return tree; },
    sends, toasts, reloads, api, saves: () => revisions };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const elements = (node, match) => !node || typeof node !== "object" ? []
  : [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap(child => elements(child, match))];
const text = node => typeof node === "string" ? node : !node || typeof node !== "object" ? "" : React.Children.toArray(node.props?.children).map(text).join("");
const button = (tree, label) => elements(tree, e => e.type === "button" && text(e).includes(label))[0];
const { DashboardAPIError } = load("@/lib/dashboard-api.ts");

const state = (spec, fields) => ({ id: "s1", revision: 3, enabled: true, reasons: [], latest: null, ...fields,
  spec: { name: "prod secrets", provider: "aws_secrets_manager", account_id: "123456789012", regions: ["ap-northeast-2"], server_collection: true, ...spec } });
const conn = (auth_method) => ({ id: "p1", provider: "aws", name: "AWS · prod", auth_method, children: [] });

test("a store's details hold what it has: rotation for a server-collected AWS store, the token for a customer-side one", () => {
  const store = load("@/console/views/vaults/store.tsx");
  const plain = value => ({ ...value });
  assert.deepEqual(plain(store.storeDetails(state({}), conn("role"), false)), { rotation: true, token: false });
  // A customer-side store registers no AWS account: nothing to read its rotation with, only its token (an Admin's).
  assert.deepEqual(plain(store.storeDetails(state({ server_collection: false }), conn("customer_cli"), true)), { rotation: false, token: true });
  assert.deepEqual(plain(store.storeDetails(state({ server_collection: false }), conn("customer_cli"), false)), { rotation: false, token: false });
  assert.deepEqual(plain(store.storeDetails(state({ provider: "vault" }), conn("token"), true)), { rotation: false, token: false });
  assert.equal(store.tokenPath({ kind: "metadata", id: "m1" }), "v2/coverage/connections/m1");
  assert.equal(store.tokenPath({ kind: "coverage", id: "c1" }), "coverage/connections/c1");
  assert.equal(store.inventoryError(new (load("@/lib/dashboard-api.ts").DashboardAPIError)("ACCOUNT_NOT_CONNECTED: no", 409), L), "이 저장소의 AWS 계정이 AWS 연동에 없습니다.");
  // The row offers the details only where there are some; the credentials no store holds page on, fifty at a time.
  const vaults = source("@/console/views/vaults/page.tsx");
  assert.match(vaults, /\{Object\.values\(storeDetails\(state, conn, admin\)\)\.some\(Boolean\)/);
  assert.match(vaults, /missing\.slice\(0, shown\)/);
  assert.match(vaults, /setShown\(value => value \+ 50\)/);
  // A read that fails after one that worked keeps the page, and an open store's details with it.
  assert.match(vaults, /const failed = \(!records\.data && records\.error\) \|\| \(!report\.data && report\.error\) \|\| \(!connections\.data && connections\.error\);/);
});

test("an AWS Secrets Manager store says which of its secrets rotate, in the inventory's region, and why not otherwise", () => {
  const store = load("@/console/views/vaults/store.tsx");
  const inventory = (fields) => ({ region: "ap-northeast-2", collection_status: "COMPLETE", total: 2, without_rotation: 1,
    secrets: [{ arn: ARN, name: "prod/app-key-AbCdEf", rotation_enabled: true }, { arn: `${ARN}x`, name: "prod/db", rotation_enabled: false }], ...fields });
  assert.match(store.inventoryText(inventory({ collection_status: "NOT_CONFIGURED", total: 0 }), L), /관리자가 AWS 연동 설정의 '발견한 Credential 조사 기능'에서 Secrets Manager 인벤토리를 켜면/);
  assert.match(store.inventoryText(inventory({ collection_status: "FAILED", total: 0 }), L), /이 계정의 Secrets Manager 목록을 읽지 못했습니다/);
  assert.match(store.inventoryText(inventory({ collection_status: "PARTIAL" }), L), /목록을 다 읽지 못했습니다 \(PARTIAL\)/);
  assert.equal(store.inventoryText(inventory({}), L), null);
  const path = "secret-managers/aws/inventory?account_id=123456789012";
  const draw = (regions, inv = inventory({})) => renderToStaticMarkup(mount("@/console/views/vaults/store.tsx", "Rotation", { api: { [path]: inv } }).draw({ accountId: "123456789012", regions }));
  const listed = draw(["ap-northeast-2"]);
  assert.match(listed, /ap-northeast-2 · Secret 2개 중 로테이션이 꺼진 1개/);
  assert.match(listed, /prod\/app-key-AbCdEf[\s\S]*켜짐[\s\S]*prod\/db[\s\S]*꺼짐/);
  // The inventory reads the installation's region: a store elsewhere is not what it lists.
  const elsewhere = draw(["us-west-2"]);
  assert.match(elsewhere, /이 설치의 리전\(ap-northeast-2\)을 읽습니다\. 이 저장소의 리전\(us-west-2\)은 읽지 않습니다/);
  assert.doesNotMatch(elsewhere, /prod\/db/);
  // Fifty at a time.
  const many = inventory({ total: 60, secrets: Array.from({ length: 60 }, (_, i) => ({ arn: `${ARN}${i}`, name: `s${i}`, rotation_enabled: false })) });
  assert.match(draw(["ap-northeast-2"], many), /60개 중 50개[\s\S]*50개 더 보기/);
});

test("a customer-side store's token is re-issued after a second click that says what follows, and kept on screen until closed", async () => {
  const child = { kind: "coverage", id: "c1", purpose: "vault", revision: 7 };
  const view = mount("@/console/views/vaults/store.tsx", "StoreModal", { replies: { "coverage/connections/c1": { collector_token: "synthetic-collector-token" } } });
  const props = { conn: conn("customer_cli"), child, state: state({ server_collection: false }, { revision: 3 }), admin: true, onClose() {} };
  let tree = view.draw(props);
  const modal = () => elements(tree, e => e.props?.labelledBy === "store-title")[0];
  const token = () => elements(tree, e => typeof e.props?.onIssued === "function")[0];
  assert.equal(modal().props.dismissable, true);
  // The two steps live in the token section: drive it directly.
  const section = mount("@/console/views/vaults/store.tsx", "CollectorToken", { replies: { "coverage/connections/c1": { collector_token: "synthetic-collector-token" } } });
  const issued = [];
  const asking = [];
  const sectionProps = { child, state: props.state, token: null, busy: false, onBusy: value => asking.push(value), onIssued: value => issued.push(value) };
  let part = section.draw(sectionProps);
  button(part, "토큰 다시 발급").props.onClick(); part = section.draw(sectionProps);
  assert.match(renderToStaticMarkup(part), /대조 범위를 다시 확정해야 하고, CLI가 새 토큰으로 수집하기 전까지/);
  button(part, "이전 토큰을 끊고 새로 발급").props.onClick(); await tick();
  // A schema 1 store's revision is the comparison report's.
  assert.deepEqual(section.sends.at(-1), ["coverage/connections/c1", "PATCH", { revision: 3, rotate_token: true }]);
  assert.deepEqual(issued, ["synthetic-collector-token"]);
  // While it is asked for, the details stay open (the previous token ends with the request).
  assert.deepEqual(asking, [true, false]);
  const modalNow = elements(view.draw(props), e => typeof e.props?.onBusy === "function")[0];
  modalNow.props.onBusy(true); tree = view.draw(props);
  assert.equal(modal().props.dismissable, false);
  assert.equal(button(tree, "닫기").props.disabled, true);
  token().props.onBusy(false); tree = view.draw(props);
  assert.equal(modal().props.dismissable, true);
  // Shown, the details no longer close on Escape or a click outside; closing them drops it.
  token().props.onIssued("synthetic-collector-token"); tree = view.draw(props);
  assert.equal(modal().props.dismissable, false);
  assert.equal(token().props.token, "synthetic-collector-token");
  assert.match(renderToStaticMarkup(section.draw({ ...sectionProps, token: "synthetic-collector-token" })), /토큰은 지금 한 번만 보여 줍니다[\s\S]*synthetic-collector-token[\s\S]*복사/);
  // With no report row, the integration's list carries the revision.
  const bare = mount("@/console/views/vaults/store.tsx", "CollectorToken", { replies: { "coverage/connections/c1": { collector_token: "t" } } });
  const bareProps = { child, state: undefined, token: null, busy: false, onBusy() {}, onIssued() {} };
  let bareTree = bare.draw(bareProps);
  button(bareTree, "토큰 다시 발급").props.onClick(); bareTree = bare.draw(bareProps);
  button(bareTree, "이전 토큰을 끊고 새로 발급").props.onClick(); await tick();
  assert.deepEqual(bare.sends.at(-1), ["coverage/connections/c1", "PATCH", { revision: 7, rotate_token: true }]);
  // A store changed since it was read is read again, so the next try carries its revision.
  const stale = mount("@/console/views/vaults/store.tsx", "CollectorToken", { replies: { "coverage/connections/c1": new DashboardAPIError("COVERAGE_REVISION_CONFLICT: changed", 409) } });
  let staleTree = stale.draw(sectionProps);
  button(staleTree, "토큰 다시 발급").props.onClick(); staleTree = stale.draw(sectionProps);
  button(staleTree, "이전 토큰을 끊고 새로 발급").props.onClick(); await tick();
  assert.equal(stale.saves(), 1);
  assert.equal(stale.toasts.at(-1)[1], "bad");
});

test("an Admin declares the secret that holds a key; the card reads again on a conflict and hides with no allowlist", async () => {
  const binding = load("@/console/views/credentials/binding.tsx");
  assert.equal(binding.secretName(ARN), "prod/app-key-AbCdEf");
  assert.equal(binding.secretName("not-an-arn"), "not-an-arn");
  assert.equal(binding.metadataError(new DashboardAPIError("ACCOUNT_NOT_CONNECTED: no", 409), L), "이 Secret이 있는 AWS 계정이 AWS 연동에 없습니다.");
  const path = "credentials/k1/management";
  const managed = (fields) => ({ revision: 2, status: "UNKNOWN", updated_at: null, can_read_metadata: false, ...fields });
  // No allowlisted secret on the installation: no card.
  assert.equal(mount("@/console/views/credentials/binding.tsx", "SecretBinding", { api: { [path]: managed({ status: "NO_MANAGER_CONNECTED" }) } })
    .draw({ credentialId: "k1", admin: true }), null);
  // A declaration answers with itself: a second change carries the new revision.
  const declared = managed({ revision: 3, status: "MANAGED_MATCHED", reference: ARN, updated_at: "2026-10-01T00:00:00Z" });
  const view = mount("@/console/views/credentials/binding.tsx", "SecretBinding", { api: { [path]: managed({}), "secret-managers": { items: [{ provider: "aws", allowed_references: [ARN] }] } },
    replies: { [path]: declared } });
  let tree = view.draw({ credentialId: "k1", admin: true });
  elements(tree, e => typeof e.props?.onChange === "function" && Array.isArray(e.props?.options))[0].props.onChange(ARN);
  tree = view.draw({ credentialId: "k1", admin: true });
  button(tree, "지정").props.onClick(); await tick();
  assert.deepEqual(view.sends.at(-1), [path, "PUT", { reference: ARN, revision: 2 }]);
  assert.equal(view.api[path].revision, 3);
  tree = view.draw({ credentialId: "k1", admin: true });
  assert.match(renderToStaticMarkup(tree), /관리자가 이 키를 prod\/app-key-AbCdEf에 보관한다고 지정했습니다\./);
  // Another Admin got there first: the card is read again.
  const conflict = mount("@/console/views/credentials/binding.tsx", "SecretBinding", { api: { [path]: declared, "secret-managers": { items: [{ provider: "aws", allowed_references: [ARN] }] } },
    replies: { [path]: new DashboardAPIError("MANAGEMENT_REVISION_CONFLICT: changed", 409) } });
  button(conflict.draw({ credentialId: "k1", admin: true }), "지정 지우기").props.onClick(); await tick();
  assert.deepEqual(conflict.sends.at(-1), [path, "DELETE", { revision: 3 }]);
  assert.deepEqual(conflict.reloads, [path]);
  // A cleared card names no date; the allowlist that failed to load says so instead of an empty choice.
  const cleared = mount("@/console/views/credentials/binding.tsx", "SecretBinding", { api: { [path]: managed({ updated_at: "2026-10-01T00:00:00Z" }),
    "secret-managers": new DashboardAPIError("boom", 500) } });
  const clearedTree = cleared.draw({ credentialId: "k1", admin: true });
  assert.equal(clearedTree.props.meta, undefined);
  assert.equal(elements(clearedTree, e => e.type?.name === "ErrorLine").length, 1);
});

test("the storage details belong to the declaration shown, and a rotation plan starts from it where the installation allows it", () => {
  const path = "credentials/k1/management/metadata";
  const metadata = (fields) => ({ reference_revision: 3, observed_at: "2026-10-01T00:00:00Z", ...fields, metadata: { arn: ARN, current_version_id: "v-1",
    rotation_enabled: true, last_rotated_date: null, next_rotation_date: null, last_accessed_date: "2026-09-30T00:00:00Z", last_changed_date: null, deleted_date: null } });
  const read = answer => mount("@/console/views/credentials/binding.tsx", "Metadata", { api: { [path]: answer } });
  assert.match(renderToStaticMarkup(read(metadata({})).draw({ credentialId: "k1", revision: 3, onStale() {} })), /로테이션[\s\S]*켜짐[\s\S]*마지막 로테이션[\s\S]*v-1/);
  // Read for another declaration than the one shown: the card is read again first.
  const stale = read(metadata({ reference_revision: 4 })).draw({ credentialId: "k1", revision: 3, onStale() {} });
  assert.equal(stale.type.name, "ErrorLine");
  assert.match(text(stale), /보관 위치가 그사이 바뀌었습니다/);
  const plans = load("@/console/views/approvals/plans.tsx");
  const policy = { rotation_secret_arns: [ARN] };
  assert.equal(plans.startSecret("PREPARE_ACCESS_KEY_ROTATION", ARN, policy), ARN);
  // Not a preparation, nothing declared, or a secret the installation does not allow: the choice starts empty.
  assert.equal(plans.startSecret("DISABLE_ACCESS_KEY", ARN, policy), "");
  assert.equal(plans.startSecret("PREPARE_ACCESS_KEY_ROTATION", undefined, policy), "");
  assert.equal(plans.startSecret("PREPARE_ACCESS_KEY_ROTATION", ARN, { rotation_secret_arns: [] }), "");
  const planSource = source("@/console/views/approvals/plans.tsx");
  assert.match(planSource, /declared=\{management\.data\?\.reference\}/);
  // A departed owner's key or another provider's credential has no declaration to read.
  assert.match(planSource, /credentialId && !provider && !path \? `credentials\/\$\{credentialId\}\/management` : null/);
  assert.match(source("@/console/views/credentials/drawer.tsx"), /<SecretBinding credentialId=\{c\.credential_id\} admin=\{session\.role === "Admin"\} \/>/);
  // The refusals the card can meet read in words.
  const data = load("@/console/data.ts");
  assert.match(data.reasonText(new DashboardAPIError("MANAGEMENT_REVISION_CONFLICT: management mapping changed since it was read", 409), L), /다른 관리자가 먼저 보관 위치를 바꿨습니다/);
  assert.match(data.reasonText(new DashboardAPIError("SECRET_METADATA_UNAVAILABLE: AccessDeniedException", 502), L), /이 Secret의 저장 정보를 읽지 못했습니다/);
  assert.match(data.reasonText(new DashboardAPIError("CONNECTION_REVISION_CONFLICT: changed", 409), L), /수집 설정이 그사이 바뀌었습니다/);
});
