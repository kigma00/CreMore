// What each feature needs, from the catalog alone: before sign-in, per feature, and with a check's answers.
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load } = require("./load-module.cjs");
const { PermissionPreview, previewRows } = load("@/console/views/integrations/permissions-preview.tsx");
const locale = load("@/components/locale.tsx");
const labelled = (label, label_ko) => ({ label, label_ko });

const d = { provider: "azure", ...labelled("Microsoft", "Microsoft"), editions: [{ id: "cloud", ...labelled("Cloud", "Cloud") }], target: [], auth_methods: [],
  purposes: {
    inventory: { permissions: [{ id: "graph", ...labelled("Graph read", "Graph 읽기") }, { id: "keys", ...labelled("Storage keys", "스토리지 키"), option: "keys" },
      { id: "sign_ins", ...labelled("Sign-in logs", "로그인 기록"), required: false }, { id: "token", ...labelled("Token admin", "토큰 관리"), methods: ["token"] }] },
    exposure: { permissions: [{ id: "graph", ...labelled("Graph read", "Graph 읽기") }, { id: "blob", ...labelled("Blob read", "Blob 읽기"), when: { storage_account: ["*"] } }] },
  } };
const method = { id: "workload_identity", ...labelled("Workload", "워크로드"), renewal: "AUTOMATIC", purposes: ["inventory", "exposure"] };
const html = (lang, props) => renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: lang },
  React.createElement(PermissionPreview, { d, method, ...props })));
const text = markup => markup.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&");

test("rows group by feature with optional, target-dependent and shared marks; other methods' permissions never appear", () => {
  const rows = previewRows(d, method.id, ["inventory", "exposure"], undefined, undefined, undefined)
    .map(g => [g.purpose, g.rows.map(r => [r.permission.id, r.optional, r.conditional, r.shared])]);
  assert.deepEqual(JSON.parse(JSON.stringify(rows)), [
    ["inventory", [["graph", false, false, false], ["keys", true, false, false], ["sign_ins", true, false, false]]],
    ["exposure", [["graph", false, false, true], ["blob", false, true, false]]],
  ]);
  // A known plan decides an option; a chosen target decides a condition.
  const chosen = previewRows(d, method.id, ["inventory", "exposure"], undefined, { exposure: [{ id: "s", target: { storage_account: "s" } }] },
    { inventory: { keys: true } }).map(g => g.rows.map(r => [r.permission.id, r.optional, r.conditional]));
  assert.deepEqual(JSON.parse(JSON.stringify(chosen)), [[["graph", false, false], ["keys", false, false], ["sign_ins", true, false]],
    [["graph", false, false], ["blob", false, false]]]);
});

test("the preview reads in Korean and English, collapsed per feature before sign-in", () => {
  const ko = html("ko", { purposes: ["inventory", "exposure"], collapsed: true });
  assert.equal((ko.match(/<details/g) ?? []).length, 2);
  assert.match(text(ko), /발급 목록 수집 \(3\)Graph 읽기스토리지 키 · 선택로그인 기록 · 선택/);
  assert.match(text(ko), /평문 노출 검사 \(2\)Graph 읽기 · 위와 같음Blob 읽기 · 대상에 따라/);
  const en = text(html("en", { purposes: ["inventory", "exposure"] }));
  assert.match(en, /Issuance inventoryGraph readStorage keys · OptionalSign-in logs · Optional/);
  assert.match(en, /Plaintext exposure scanGraph read · Same as aboveBlob read · Depends on target/);
  assert.doesNotMatch(en, /Token admin/);
  assert.match(text(html("en", { purposes: ["exposure"], collapsed: true })), /^Permissions needed \(2\)/);
});

test("result mode marks each answer, per target where they differ, and an unanswered required permission as unverified", () => {
  const targets = { exposure: [{ id: "a", label: "store-a", target: { storage_account: "a" } }, { id: "b", label: "store-b", target: { storage_account: "b" } }] };
  const results = { exposure: { status: "MISSING", items: [{ permission: "blob", status: "GRANTED", target_id: "a" },
    { permission: "blob", status: "MISSING", target_id: "b", detail: "HTTP_403" }] } };
  const markup = html("en", { purposes: ["exposure"], targets, results });
  assert.match(markup, /perm-none[^>]*>.*?Graph read/, "no answer for a required permission reads as not reported");
  assert.match(markup, /perm-ok[^>]*>.*?Blob read · store-a/);
  assert.match(markup, /perm-bad[^>]*data-tip="blob · Missing · This read was denied[^"]*store-b"/);
  assert.match(text(html("ko", { purposes: ["exposure"], targets, results })), /Blob 읽기 · store-b/);
});

// Faithful copies of cremore.onboarding.catalog.public() entries (AWS vault, Notion inventory, GCP inventory).
const AWS_METHODS = ["role", "sso", "runtime"];
const aws = { provider: "aws", ...labelled("AWS", "AWS"), editions: [{ id: "cloud", ...labelled("Cloud", "Cloud") }], target: [], auth_methods: [],
  purposes: { vault: { permissions: [
    { id: "secrets_values", ...labelled("secretsmanager:GetSecretValue", "Secrets Manager 값 읽기"), methods: AWS_METHODS },
    { id: "ssm_values", ...labelled("ssm:GetParametersByPath with decryption", "Parameter Store 값 복호화 읽기"), methods: AWS_METHODS, nonempty: "ssm_prefixes" },
    { id: "secrets_list", ...labelled("List Secrets Manager secrets", "Secrets Manager 시크릿 목록"), methods: AWS_METHODS, unless: "value_reader" },
    { id: "ssm_list", ...labelled("List Parameter Store parameters", "Parameter Store 파라미터 목록"), methods: AWS_METHODS, nonempty: "ssm_prefixes", unless: "value_reader" }],
  plan: [{ name: "ssm_prefixes", kind: "list", default: null, ...labelled("Prefixes", "접두어") },
    { name: "value_reader", kind: "bool", default: false, ...labelled("Value reader", "값 읽기 역할") }] } } };
const notion = { provider: "notion", ...labelled("Notion", "Notion"), editions: ["standard", "enterprise", "cloud"].map(id => ({ id, ...labelled(id, id) })), target: [], auth_methods: [],
  purposes: { inventory: { permissions: [
    { id: "workspace_tokens", ...labelled("Read personal access tokens (personal-access-token:read)", "개인 액세스 토큰 읽기(personal-access-token:read)"), option: "personal_access_tokens" },
    { id: "mcp_connections", ...labelled("Read MCP connections (mcp-client-connection:read)", "MCP 연결 목록 읽기(mcp-client-connection:read)"), option: "mcp_connections" }],
  plan: [{ name: "personal_access_tokens", kind: "bool", default: true, ...labelled("Personal access tokens", "개인 액세스 토큰") },
    { name: "mcp_connections", kind: "bool", default: false, ...labelled("MCP connections", "MCP 연결") }] } } };
const project = { scope: ["project"] }, GCP_METHODS = ["adc", "google_oauth"];
const gcp = { provider: "gcp", ...labelled("Google Cloud", "Google Cloud"), editions: [{ id: "cloud", ...labelled("Cloud", "Cloud") }], target: [], auth_methods: [],
  purposes: { inventory: { permissions: [
    { id: "iam.serviceAccounts.list", ...labelled("iam.serviceAccounts.list", "iam.serviceAccounts.list"), when: project, methods: GCP_METHODS },
    { id: "resourcemanager.projects.getIamPolicy", ...labelled("resourcemanager.projects.getIamPolicy", "resourcemanager.projects.getIamPolicy"), when: project, methods: GCP_METHODS, option: "service_account_iam" },
    { id: "resourcemanager.projects.getIamPolicy", ...labelled("resourcemanager.projects.getIamPolicy", "resourcemanager.projects.getIamPolicy"), when: project, methods: GCP_METHODS, option: "effective_access" },
    { id: "resourcemanager.projects.list", ...labelled("resourcemanager.projects.list", "resourcemanager.projects.list"), when: { scope: ["organization", "folder"] } }],
  plan: [{ name: "service_account_iam", kind: "bool", default: false, when: project, ...labelled("Service account IAM", "서비스 계정 IAM") },
    { name: "effective_access", kind: "bool", default: false, when: project, ...labelled("Effective access", "실효 권한") }] } } };
const marks = (descriptor, purpose, method, edition, plans) => Object.fromEntries(previewRows(descriptor, method, [purpose], undefined, undefined, plans, edition)[0]
  .rows.map(r => [r.permission.id, r.optional]));

test("'선택' follows the edition's default plan: an unless that is off and an option on by default are required", () => {
  assert.deepEqual(marks(aws, "vault", "role", "cloud"), { secrets_values: false, ssm_values: true, secrets_list: false, ssm_list: true },
    "listing secrets is required unless the value reader is on; Parameter Store needs prefixes");
  assert.deepEqual(marks(notion, "inventory", "organization_bot", "enterprise"), { workspace_tokens: false, mcp_connections: true },
    "personal access tokens are read by default");
  // A chosen plan decides instead: with the value reader on, listing secrets is not asked for at all.
  assert.equal("secrets_list" in marks(aws, "vault", "role", "cloud", { vault: { value_reader: true, ssm_prefixes: "" } }), false);
  const ko = text(renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" },
    React.createElement(PermissionPreview, { d: aws, method: { id: "role", purposes: ["vault"] }, edition: "cloud", purposes: ["vault"] }))));
  assert.match(ko, /Secrets Manager 시크릿 목록(?! · 선택)/);
  assert.match(ko, /Parameter Store 파라미터 목록 · 선택/);
});

test("a permission declared under several options is one row, judged for the targets its condition names", () => {
  assert.deepEqual(marks(gcp, "inventory", "adc", "cloud"), { "iam.serviceAccounts.list": false, "resourcemanager.projects.getIamPolicy": true,
    "resourcemanager.projects.list": false });
  const ko = text(renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" },
    React.createElement(PermissionPreview, { d: gcp, method: { id: "adc", purposes: ["inventory"] }, purposes: ["inventory"], collapsed: true }))));
  assert.match(ko, /^필요한 권한 \(3\)/);
  assert.equal(ko.match(/getIamPolicy/g).length, 1);
});
