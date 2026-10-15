"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;
const EN = (_ko, en) => en;
// Shapes as the API serves them: a schema 2 fact (cremore/coverage/metadata_models.py MetadataFact), an entity detail
// (metadata_store.entity_detail), and an identity policy reading as the usage lookup keeps it
// (aws/.../investigation/identity_policies.py, potential_access.py through usage.potential_access_view).
const fact = (fields) => ({ name: "status", state: "PRESENT", value: "ACTIVE", container: null, children: [], reason: null, ...fields });
const body = (fields) => ({ facts: [fact({})], omissions: [], permissions: [], provider_state: "active", normalized_state: "ACTIVE", state_basis: "PROVIDER_REPORTED", ...fields });
const detail = (fields) => ({
  entity: { id: "e1", provider: "notion", origin: "https://api.notion.com", tenant: "acme-tenant", tenant_confirmed: false, object_kind: "credential",
    object_id: "pat:1", purpose: "issuer_inventory", observed_at: "2026-09-30T00:00:00Z", first_observed_at: "2026-09-01T00:00:00Z", summary: body({}) },
  collections: [], current_record: { id: "r1", body: body({}) }, last_success_record: { id: "r1", body: body({}) }, ...fields });
const statement = (fields) => ({ sid: "", effect: "Allow", actions: [], not_actions: [], resources: ["*"], not_resources: [], condition_keys: [], truncated: false, ...fields });
const policies = (fields) => ({ collection_status: "COMPLETE", principal_arn: "arn:aws:iam::123456789012:user/ci", principal_type: "IAM_USER", policies: [], errors: [], ...fields });
const simulated = (action, risk, decision = "ALLOWED") => ({ action, service: action.split(":")[0], decision, risk, missing_context_values: [] });
const usage = (fields) => ({ collection_status: "COMPLETE", events: [], ...fields,
  ...(fields.potential_access ? { potential_access: { assessment_version: 2, ...fields.potential_access } } : {}) });

function html(element) {
  const locale = load("@/components/locale.tsx");
  return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" }, element));
}

test("an issued item's fields read as the service returned them: a value, a nested set, or why there is none", () => {
  const issued = load("@/console/views/credentials/issued.tsx");
  assert.equal(issued.factValue(fact({}), L, "ko"), "ACTIVE");
  assert.equal(issued.factValue(fact({ value: ["repo", "workflow"] }), L, "ko"), "repo, workflow");
  assert.equal(issued.factValue(fact({ value: false }), L, "ko"), "false");
  assert.equal(issued.factValue(fact({ state: "NULL", value: null }), L, "ko"), "값 없음");
  assert.equal(issued.factValue(fact({ state: "NULL", value: null }), EN, "en"), "No value");
  assert.equal(issued.factValue(fact({ state: "MISSING", value: null }), L, "ko"), "응답에 없음");
  // Why a field is malformed reads in words, as the collection screens word it.
  assert.equal(issued.factValue(fact({ state: "INVALID", value: null, reason: "INVALID_METADATA_VALUE" }), L, "ko"), "형식 오류 · 저장할 수 없는 형식의 값");
  assert.equal(issued.factValue(fact({ state: "INVALID", value: null, reason: "INVALID_METADATA_TIME" }), L, "ko"), "형식 오류 · 저장할 수 없는 형식의 시각");
  // A nested set renders as its own list; an empty one says so rather than reading as an empty value.
  assert.equal(issued.factValue(fact({ value: null, container: "object", children: [fact({ name: "id" })] }), L, "ko"), null);
  assert.equal(issued.factValue(fact({ value: null, container: "array" }), L, "ko"), "빈 목록");
  assert.equal(issued.factValue(fact({ value: null, container: "object" }), L, "ko"), "빈 항목");
});

test("an issued item's state reads in words, with the service's own word only where it says more", () => {
  const issued = load("@/console/views/credentials/issued.tsx");
  assert.equal(issued.stateText({ provider_state: "ACTIVE", normalized_state: "ACTIVE" }, L), "활성");
  assert.equal(issued.stateText({ provider_state: "suspended_by_admin", normalized_state: "DISABLED" }, L), "사용 중지 · suspended_by_admin");
  assert.equal(issued.stateText({ provider_state: "UNKNOWN", normalized_state: "UNKNOWN" }, L), null);
  // An entity whose current observation is gone has no summary; that is no state, not a crash.
  assert.equal(issued.stateText(null, L), null);
  assert.deepEqual([...issued.runText("PARTIAL", L)], ["일부", "partial"]);
  assert.deepEqual([...issued.runText("NOT_COLLECTED", L)], ["수집 전", "partial"]);
  assert.deepEqual([...issued.runText("SOMETHING_NEW", L)], ["SOMETHING_NEW", undefined]);
});

test("the issued item shows where it was collected, what saw it, its permissions and its observations", () => {
  const issued = load("@/console/views/credentials/issued.tsx");
  const view = (fields) => html(React.createElement(issued.IssuedDetailView, { d: detail(fields) }));
  // Tenancy the service did not confirm is not shown as tenancy: the origin is.
  const unconfirmed = view({});
  assert.ok(unconfirmed.split(/[<>]/).some(text => text === "https://api.notion.com"));
  assert.doesNotMatch(unconfirmed, /acme-tenant/);
  assert.match(view({ entity: { ...detail({}).entity, tenant_confirmed: true } }), /acme-tenant/);
  // Why a collection's view may be dated reads in words: the store's own reasons and a run's.
  const seen = view({ collections: [{ connection_id: "c1", name: "notion", status: "PARTIAL", finished_at: "2026-09-30T00:00:00Z",
    reasons: ["CONNECTION_SCOPE_CHANGED", "SOURCE_COVERAGE_NOT_REPORTED"] }] });
  assert.match(seen, /이 항목을 관측한 수집/);
  assert.match(seen, /설정을 바꾼 뒤 아직 수집하지 않음 · 수집이 읽은 범위를 보고하지 않아 일부로 봄/);
  // Permissions only where the observation has them.
  assert.doesNotMatch(unconfirmed, /권한과 범위/);
  const granted = view({ current_record: { id: "r1", body: body({ permissions: [{ kind: "scope", name: "read_content", resource_kind: "workspace", resource_id: "w1",
    effect: "ALLOW", actions: ["read"], conditions: [] }] }) } });
  assert.match(granted, /권한과 범위/);
  assert.match(granted, /read_content/);
  assert.match(granted, /workspace: w1/);
  // Evaluation facts read as Google's answer and what it rested on, never as a count of conditions.
  const answered = view({ current_record: { id: "r1", body: body({ permissions: [
    { kind: "permission", name: "storage.objects.delete", resource_kind: "project", resource_id: "projects/p", effect: "DENY", actions: [],
      conditions: [fact({ name: "effective_access", value: "cannot_access" }), fact({ name: "deny_policies", value: "denied" })] },
    { kind: "permission", name: "storage.objects.get", resource_kind: "project", resource_id: "projects/p", effect: "UNKNOWN", actions: [],
      conditions: [fact({ name: "effective_access", value: "not_evaluated" }), fact({ name: "error_code", value: "api_disabled" })] },
    { kind: "role", name: "Reader · /subscriptions/s/resourceGroups/rg", resource_kind: "azure_scope", resource_id: "/subscriptions/s/resourceGroups/rg",
      effect: "ALLOW", actions: [], conditions: [fact({ name: "membership_resolution", value: "group_member" }), fact({ name: "condition_present", value: true })] }] }) } });
  assert.match(answered, /접근 불가/);
  assert.match(answered, /거부 정책 적용/);
  assert.match(answered, /판정하지 못함/);
  assert.match(answered, /API가 꺼져 있음/);
  assert.match(answered, /그룹으로 받음 · 조건부 할당/);
  assert.doesNotMatch(answered, /조건 \d+개/);
  // The last successful observation only where it differs from the current one; a field not kept says why in words.
  assert.doesNotMatch(unconfirmed, /마지막 성공 관측/);
  assert.match(view({ last_success_record: { id: "r0", body: body({}) } }), /마지막 성공 관측/);
  assert.match(view({ current_record: { id: "r1", body: body({ omissions: [{ path: "/extra", reason: "METADATA_FACT_LIMIT" },
    { path: "/raw", reason: "UNAPPROVED_METADATA_FIELD" }] }) } }),
    /\/extra \(필드가 너무 많아 나머지는 저장하지 않음\), \/raw \(저장할 수 있는 필드 목록에 없음\)/);
  // No current observation: no state, and the last observation says so.
  const gone = view({ entity: { ...detail({}).entity, summary: null, observed_at: null }, current_record: null, last_success_record: null });
  assert.match(gone, /현재 관측 없음/);
  assert.match(gone, /알 수 없음/);
});

test("what a policy allows reads as the backend counts it: every action only for an unconditional * on *", () => {
  const perms = load("@/console/views/credentials/permissions.tsx");
  assert.equal(perms.everything(statement({ actions: ["*"] })), true);
  assert.equal(perms.everything(statement({ actions: ["*"], condition_keys: ["StringEquals:aws:RequestedRegion"] })), false);
  assert.equal(perms.everything(statement({ actions: ["*"], resources: [], not_resources: ["arn:aws:s3:::audit/*"] })), false);
  assert.equal(perms.allowsText([statement({ actions: ["*"] })], L), "모든 작업");
  assert.equal(perms.allowsText([statement({ actions: ["*"], condition_keys: ["StringEquals:aws:RequestedRegion"] })], L), "조건이 맞을 때 모든 작업 · 조건부 문장 1개");
  // NotResource grants everything but the named resources: never "named resources only".
  assert.equal(perms.allowsText([statement({ actions: ["*"], resources: [], not_resources: ["arn:aws:s3:::audit/*"] })], L), "모든 작업 · arn:aws:s3:::audit/* 제외 모든 리소스");
  assert.equal(perms.allowsText([statement({ actions: ["s3:PutObject"], resources: ["arn:aws:s3:::app/*"] })], L), "s3:PutObject · 지정한 리소스에만");
  assert.equal(perms.allowsText([statement({ not_actions: ["iam:*"] })], L), "iam:* 제외 모든 작업");
  // `*` without a condition only on named resources says so, whatever a conditional statement beside it allows.
  assert.equal(perms.allowsText([statement({ actions: ["*"], resources: ["arn:aws:s3:::app/*"] }),
    statement({ actions: ["*"], condition_keys: ["Bool:aws:MultiFactorAuthPresent"] })], L), "지정한 리소스에서 모든 작업 · 조건부 문장 1개");
  assert.equal(perms.allowsText([statement({ actions: ["*"], resources: ["arn:aws:s3:::app/*"] })], L), "지정한 리소스에서 모든 작업");
  assert.equal(perms.allowsText([statement({ actions: ["s3:GetObject"] }), statement({ effect: "Deny", actions: ["s3:DeleteObject"] })], EN), "s3:GetObject · 1 deny statement");
});

test("an AWS key's permissions read from its lookup: identity policies, then the actions IAM's simulator allows", () => {
  const perms = load("@/console/views/credentials/permissions.tsx");
  const u = usage({
    identity_policies: policies({ policies: [
      { source: "MANAGED_USER", name: "ReadOnlyS3", statements: [statement({ actions: ["s3:Get*", "s3:List*"] })] },
      { source: "INLINE_USER", name: "deploy", statements: [statement({ actions: ["s3:PutObject"], resources: ["arn:aws:s3:::app/*"] })] },
      { source: "INLINE_USER", name: "lowercase", statements: [statement({ actions: ["s3:getobject", "ec2:describe*"] })] },
      { source: "MANAGED_GROUP", name: "ReadOnlyAccess", group: "devs", statements: [statement({ actions: ["s3:Get*"] })] },
      { source: "MANAGED_GROUP", name: "ReadOnlyAccess", group: "ops", statements: [statement({ actions: ["s3:Get*"] })] },
      { source: "PERMISSIONS_BOUNDARY", name: "boundary", statements: [statement({ actions: ["*"] })] },
    ] }),
    potential_access: { collection_status: "COMPLETE", actions: [simulated("iam:CreateAccessKey", "PRIVILEGE_ESCALATION"), simulated("kms:Decrypt", "SECRET_ACCESS"),
      simulated("s3:GetObject", "READ"), simulated("iam:DeleteUser", "DESTRUCTIVE", "IMPLICIT_DENY")] },
  });
  const rows = [...perms.permissionRows(u, L)];
  assert.deepEqual(rows.map(row => [row.permission, row.allows, row.tag, row.source]), [
    ["ReadOnlyS3", "s3:Get*, s3:List*", null, "사용자 관리형 정책"],
    ["deploy", "s3:PutObject · 지정한 리소스에만", "쓰기", "사용자 인라인 정책"],
    // IAM action names are case-insensitive: a read written in lower case is a read.
    ["lowercase", "s3:getobject, ec2:describe*", null, "사용자 인라인 정책"],
    // The same managed policy through two groups is two rows, each naming its group.
    ["ReadOnlyAccess", "s3:Get*", null, "그룹 관리형 정책 · devs"],
    ["ReadOnlyAccess", "s3:Get*", null, "그룹 관리형 정책 · ops"],
    // A boundary grants nothing: it is the most the others may allow, never a write.
    ["boundary", "최대 범위: 모든 작업", null, "권한 경계"],
    // Simulated denials are retained, with no risk tag or assertion of actual access.
    ["iam:CreateAccessKey", "허용 (잠재 권한)", "권한 상승", "정책 시뮬레이션"],
    ["kms:Decrypt", "허용 (잠재 권한)", "비밀 읽기", "정책 시뮬레이션"],
    ["s3:GetObject", "허용 (잠재 권한)", null, "정책 시뮬레이션"],
    ["iam:DeleteUser", "허용 근거 없음 (시뮬레이션)", null, "정책 시뮬레이션"],
  ]);
  assert.equal(new Set(rows.map(row => row.key)).size, rows.length);
  // A reading that stopped short still lists what it read; one that failed, or never ran, lists nothing.
  assert.equal(perms.permissionRows(usage({ identity_policies: policies({ collection_status: "PARTIAL", policies: [{ source: "INLINE_USER", name: "kept",
    statements: [statement({ actions: ["s3:GetObject"] })] }] }) }), L).length, 1);
  // A policy whose statements all fell past the stored 300 says so rather than reading as allowing nothing.
  const [cut] = [...perms.permissionRows(usage({ identity_policies: policies({ statements_truncated: true, policies: [{ source: "MANAGED_USER",
    name: "AdministratorAccess", statements: [] }] }) }), L)];
  assert.equal(cut.allows, "앞의 300개 문장 밖이라 보여 주지 않습니다");
  // A simulation that stopped short keeps the actions it decided.
  assert.deepEqual([...perms.permissionRows(usage({ potential_access: { collection_status: "PARTIAL", error_code: "Throttling",
    actions: [simulated("iam:CreateAccessKey", "PRIVILEGE_ESCALATION")] } }), L)].map(row => row.permission), ["iam:CreateAccessKey"]);
  assert.equal(perms.permissionRows(usage({ collection_status: "NOT_COLLECTED" }), L).length, 0);
  assert.equal(perms.permissionRows(usage({ identity_policies: policies({ collection_status: "FAILED" }), potential_access: { collection_status: "FAILED", actions: [] } }), L).length, 0);
});

test("what the reading carries beside the rows: the gravest first, then what bounds it, then what there was", () => {
  const perms = load("@/console/views/credentials/permissions.tsx");
  const summary = (fields) => ({ quarantine_policies: [], deny_all_policies: [], allow_all_policies: [], permissions_boundary: false, boundary_limits_allow_all: false,
    allow_statements: 1, deny_statements: 0, conditional_statements: 0, allowed_actions: [], allowed_actions_truncated: false, ...fields });
  const notes = (u) => [...perms.permissionNotes(u, L)].map(note => `${note.tone ?? "info"}:${note.text}`);
  assert.deepEqual(notes(usage({ identity_policies: policies({ policies: [{}], summary: summary({ allow_all_policies: ["AdministratorAccess"] }) }) })),
    ["bad:모든 작업을 허용하는 정책이 있습니다: AdministratorAccess"]);
  assert.deepEqual(notes(usage({ identity_policies: policies({ policies: [{}], summary: summary({ allow_all_policies: ["AdministratorAccess"], permissions_boundary: true, boundary_limits_allow_all: true }) }) })),
    ["warn:모든 작업을 허용하는 정책(AdministratorAccess)이 있지만 권한 경계가 좁힙니다."]);
  // The genuine AWS-managed policy can be attached by a customer. Its presence
  // proves neither the attaching actor nor exposure of this specific key.
  assert.deepEqual(notes(usage({ identity_policies: policies({ policies: [{}], summary: summary({ quarantine_policies: ["AWSCompromisedKeyQuarantineV3"], deny_all_policies: ["DenyEverything"] }) }) })),
    ["warn:주체에 AWS 격리 정책이 연결되어 있습니다: AWSCompromisedKeyQuarantineV3. 연결한 주체와 이 키의 노출 여부는 확인되지 않았습니다.", "warn:모든 작업을 거부하는 정책 문장이 관측되었습니다: DenyEverything"]);
  const flagged = usage({ identity_policies: policies({ policies: [{}], summary: summary({ quarantine_policies: ["AWSCompromisedKeyQuarantineV3"] }) }) });
  assert.match(perms.permissionNotes(flagged, EN)[0].text, /policy is attached.*attaching actor.*not established/);
  const { stageText } = load("@/console/views/credentials/tabs.tsx", { extraExports: "\nexport { stageText };" });
  const stage = { stage: "PRIVILEGED", state: "OBSERVED", quarantine_policies: ["AWSCompromisedKeyQuarantineV3"] };
  assert.equal(stageText(stage, L), "AWS 격리 정책 연결 관측 · 키 노출 근거 아님");
  assert.equal(stageText(stage, EN), "AWS quarantine policy attached · not evidence of key exposure");
  assert.deepEqual(notes(usage({ identity_policies: policies({ collection_status: "PARTIAL", policies: [{}], errors: [{ step: "ListGroupsForUser", error_code: "AccessDenied" }] }) })),
    ["warn:정책 일부를 읽지 못했습니다 (AccessDenied)."]);
  assert.deepEqual(notes(usage({ identity_policies: policies({ collection_status: "FAILED" }) })), ["warn:이 키 주체의 정책을 읽지 못했습니다."]);
  assert.match(notes(usage({ identity_policies: policies({ policies: [{}], statements_truncated: true }) }))[0], /^warn:정책 문장이 많아 앞의 300개만 보여 줍니다/);
  // A root key is not limited by IAM policies; its simulation is not run either, which is said once.
  assert.deepEqual(notes(usage({ identity_policies: policies({ collection_status: "NOT_APPLICABLE", principal_type: "ROOT" }),
    potential_access: { collection_status: "UNSUPPORTED", actions: [] } })), ["bad:루트 사용자의 키입니다. IAM 정책으로 제한되지 않습니다."]);
  assert.deepEqual(notes(usage({ identity_policies: policies({ collection_status: "UNSUPPORTED", principal_type: "UNKNOWN" }) })), ["info:이 주체 유형은 IAM 정책을 읽지 않습니다."]);
  assert.deepEqual(notes(usage({ identity_policies: policies({}) })), ["info:이 키 주체에 붙은 IAM 정책이 없습니다."]);
  // Read before the owning account was confirmed, whichever part was read; a session key's simulation is its role's.
  assert.deepEqual(notes(usage({ collection_status: "ACCOUNT_UNVERIFIED", potential_access: { collection_status: "COMPLETE", actions: [] } })),
    ["warn:소유 계정을 확인하기 전에 읽은 정책입니다."]);
  assert.match(notes(usage({ potential_access: { collection_status: "COMPLETE", evaluated_role_arn: "arn:aws:iam::123456789012:role/app", actions: [] } }))[0],
    /^info:세션 키라서 맡은 역할\(arn:aws:iam::123456789012:role\/app\)의 잠재 권한입니다/);
  assert.deepEqual(notes(usage({ potential_access: { collection_status: "FAILED", error_code: "AccessDenied", actions: [] } })), ["warn:권한 시뮬레이션을 마치지 못했습니다 (AccessDenied)."]);
  assert.deepEqual(notes(usage({ potential_access: { collection_status: "PARTIAL", error_code: "Throttling", actions: [] } })),
    ["warn:권한 시뮬레이션이 일부 작업만 판단했습니다 (Throttling)."]);
  // A partial simulation of a session key is still its role's, and still read before the account was confirmed.
  assert.deepEqual(notes(usage({ collection_status: "ACCOUNT_UNVERIFIED", potential_access: { collection_status: "PARTIAL", evaluated_role_arn: "arn:aws:iam::123456789012:role/app", actions: [] } }))
    .map(note => note.split(":")[0]), ["warn", "info", "warn"]);
  assert.deepEqual(notes(usage({})), []);
});

test("the permissions card body: notes over rows, and a key never looked up says how it is read", () => {
  const perms = load("@/console/views/credentials/permissions.tsx");
  const view = (u) => html(React.createElement(perms.PermissionsView, { u }));
  const root = view(usage({ identity_policies: policies({ collection_status: "NOT_APPLICABLE", principal_type: "ROOT" }) }));
  assert.match(root, /class="banner bad"/);
  assert.doesNotMatch(root, /<table/);
  assert.match(view(usage({ collection_status: "NOT_COLLECTED" })), /사용 기록을 조회하면 이 키 주체의 IAM 정책을 읽습니다/);
  const listed = view(usage({ identity_policies: policies({ policies: [{ source: "INLINE_USER", name: "deploy", statements: [statement({ actions: ["s3:PutObject"] })] }] }) }));
  assert.match(listed, /<table class="sub-tbl">/);
  assert.match(listed, /deploy/);
  assert.doesNotMatch(listed, /사용 기록을 조회하면/);
  const collapsed = view(usage({ potential_access: { collection_status: "COMPLETE", actions: [simulated("iam:CreateAccessKey", "PRIVILEGE_ESCALATION")] } }));
  assert.match(collapsed, /정책 시뮬레이션 · 평가 1개/);
  assert.match(collapsed, /aria-expanded="false"/);
  assert.doesNotMatch(collapsed, /iam:CreateAccessKey/);
});

test("an issued item opens where the credentials are, from search, a credential's issuance links and its menu", () => {
  // Search takes an issued or stored object to the item itself, over the credential list.
  assert.match(source("@/console/search.tsx"), /hit\.kind === "managed_object"\) go\("inventory", \{ entity: hit\.id \}\)/);
  // The list shows it from its link whether or not the list itself has loaded.
  const list = source("@/console/views/credentials/list.tsx");
  assert.match(list, /const issued = entity \? <IssuedItemModal key=\{entity\} entityId=\{entity\} onClose=\{\(\) => setParams\(\{ entity: null \}\)\} \/> : null;/);
  assert.match(list, /<Loading \/>\{issued\}<\/>/);
  assert.match(list, /<\/ErrorLine>\{issued\}<\/>/);
  // The panel's links and menu open it over the panel, wherever the panel is open (credential list, assignment);
  // none points at a screen that does not read the item.
  const tabs = source("@/console/views/credentials/tabs.tsx");
  const drawer = source("@/console/views/credentials/drawer.tsx");
  for (const text of [tabs, drawer, source("@/console/search.tsx")]) assert.doesNotMatch(text, /view=metadata&entity|go\("metadata", \{ entity/);
  assert.match(tabs, /onClick=\{\(\) => openIssued\(item\.entity_id\)\}/);
  assert.match(drawer, /<OverviewTab [^>]*openIssued=\{entity => setModal\(\{ kind: "issued", entity \}\)\}/);
  assert.match(drawer, /setModal\(\{ kind: "issued", entity: c\.issued!\.entity_id! \}\); \}\}>\{L\("발급 항목 보기", "View the issued item"\)\}/);
  assert.match(drawer, /\{modal\?\.kind === "issued" \? <IssuedItemModal entityId=\{modal\.entity\} onClose=\{\(\) => setModal\(null\)\} \/> : null\}/);
  // The item's own route; an error reads as one.
  const issued = source("@/console/views/credentials/issued.tsx");
  assert.match(issued, /`v2\/coverage\/inventory\/\$\{encodeURIComponent\(entityId\)\}\?limit=1`/);
  assert.match(issued, /view\.error \? <ErrorLine onRetry=\{view\.reload\}>/);
});

test("the permissions card lists an AWS key's policies from its lookup when the service gives no scopes", () => {
  const tabs = source("@/console/views/credentials/tabs.tsx");
  assert.match(tabs, /c\.scopes\?\.length \? <div className="sub-scroll">[\s\S]*?: usageLookup\(c\) \? <LookupPermissions c=\{c\} \/>/);
  const perms = load("@/console/views/credentials/permissions.tsx");
  const lookup = { provider: "aws", aws_permissions: { identity_policies: policies({ policies: [{ source: "INLINE_USER", name: "deploy", statements: [] }] }) } };
  assert.match(html(React.createElement(perms.LookupPermissions, { c: lookup })), /deploy/);
  const inventory = { provider: "aws", issued: { provider: "aws_iam", current: true,
    iam_policies: { status: "COMPLETE", policy_names: ["AdministratorAccess"], allow_actions: ["*"], deny_statements: 0, conditional_statements: 0 } } };
  assert.match(html(React.createElement(perms.LookupPermissions, { c: inventory })), /IAM 정책 1개/);
  assert.doesNotMatch(html(React.createElement(perms.LookupPermissions, { c: inventory })), /사용 기록을 조회하면/);
});
