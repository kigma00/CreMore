// CreMore's GitHub App on an enterprise's other organizations: which connections offer it, the GitHub pages each
// step opens on GitHub.com, GHE.com and GitHub Enterprise Server, and how each refusal reads. Synthetic values only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const enterprise = load("@/console/views/integrations/github-enterprise.tsx");
const L = (ko, en) => ko;
// Values made in the loaded module's realm compare by structure once they are plain JSON.
const plain = value => JSON.parse(JSON.stringify(value));

const connection = extra => ({ id: "c1", provider: "github", auth_method: "github_app", status: "ACTIVE",
  purposes: ["inventory"],
  target: { organization: "acme", enterprise: "acme-corp" }, credential: { roles: ["credential"], reference: false }, ...extra });

test("only a GitHub App connection that names its enterprise and holds its own key offers it", () => {
  assert.equal(enterprise.enterpriseReady(connection()), true);
  assert.equal(enterprise.enterpriseReady(connection({ target: { organization: "acme" } })), false);
  assert.equal(enterprise.enterpriseReady(connection({ auth_method: "token" })), false);
  assert.equal(enterprise.enterpriseReady(connection({ target: { version: 2, roots: [], auth: { github_enterprise: "acme-corp" } } })), true);
  assert.equal(enterprise.enterpriseReady(connection({ purposes: ["remediation"] })), false);
  assert.equal(enterprise.enterpriseReady(connection({ status: "DISABLED" })), false);
  assert.equal(enterprise.enterpriseReady(connection({ credential: { roles: ["credential"], reference: true } })), false);
  assert.equal(enterprise.enterprisePath("c1"), "provider-connections/c1/github-enterprise");
});

test("each step opens its page on the connection's GitHub", () => {
  const status = { organization: "acme", enterprise: "acme-corp", app: { slug: "cremore-acme" } };
  assert.deepEqual(plain(enterprise.githubPages({ ...status, host: null })), {
    transfer: "https://github.com/organizations/acme/settings/apps/cremore-acme/advanced",
    permissions: "https://github.com/enterprises/acme-corp/settings/apps",
    install: "https://github.com/apps/cremore-acme/installations/new" });
  assert.equal(enterprise.githubPages({ ...status, host: "acme.ghe.com" }).install, "https://acme.ghe.com/apps/cremore-acme/installations/new");
  assert.equal(enterprise.githubPages({ ...status, host: "https://github.example.com/" }).install,
    "https://github.example.com/github-apps/cremore-acme/installations/new");
  // Before the transfer the App's settings sit under the organization that owns it, which need not be this one.
  assert.equal(enterprise.githubPages({ ...status, host: null, app: { slug: "cremore-acme", owner: "acme-platform", owner_type: "Organization" } }).transfer,
    "https://github.com/organizations/acme-platform/settings/apps/cremore-acme/advanced");
});

test("each refusal reads as what to check", () => {
  assert.match(enterprise.codeText("GITHUB_ENTERPRISE_INSTALL_REFUSED", L), /엔터프라이즈 소유인지/);
  assert.match(enterprise.codeText("GITHUB_ENTERPRISE_PERMISSION_REQUIRED", L), /엔터프라이즈 조직 설치 권한/);
  assert.match(enterprise.codeText("GITHUB_ENTERPRISE_NOT_FOUND", L), /3\.19 이상/);
  assert.match(enterprise.codeText("GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE", L), /알려 주지 않은 조직/);
  assert.match(enterprise.codeText("GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE", L), /수집을 시작/);
  assert.equal(enterprise.codeText("SOMETHING_NEW", L), "SOMETHING_NEW");
});

test("a refreshing worker snapshot waits without invented setup links and retains polling", () => {
  const React = require("react");
  const base = { enterprise: "acme-corp", organization: "acme", source_status: "ACTIVE", host: null,
    state: "REFRESHING", refresh_pending: true, app: null, organizations: [], made: [] };
  let data = base, polling;
  const { GitHubEnterpriseModal } = load("@/console/views/integrations/github-enterprise.tsx", { overrides: {
    react: { ...React, useState: value => [value, () => {}] },
    "@/console/data": { useApi: (_path, options) => { polling = options?.every; return { data }; }, useSaved: () => () => {} },
    "@/console/layer": { ...load("@/console/layer.tsx"), useToast: () => () => {} },
    "@/console/text": { ...load("@/console/text.ts"), useL: () => (_ko, en) => en },
    "@/components/locale": { useLocale: () => "en" },
  } });
  const elements = (node, match) => !node || typeof node !== "object" ? []
    : [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap(child => elements(child, match))];
  const text = node => typeof node === "string" ? node : !node || typeof node !== "object" ? ""
    : React.Children.toArray(node.props?.children).map(text).join("");
  const render = () => GitHubEnterpriseModal({ conn: connection(), onClose() {} });
  let tree = render();
  assert.match(text(elements(tree, n => n.props.role === "status")[0]), /worker is checking/);
  assert.equal(elements(tree, n => n.props.href).length, 0);
  assert.notEqual(polling, 0, "useApi default polling remains enabled");
  assert.equal(enterprise.githubPages(base).install, undefined);
  assert.equal(enterprise.githubPages(base).transfer, undefined);
  data = { ...base, state: "READY", app: { slug: "cremore" } };
  tree = render();
  assert.match(text(tree), /previous result/);
  assert.equal(elements(tree, n => n.type === "table").length, 1, "stale snapshot remains visible");
  data = { ...data, refresh_pending: false };
  assert.doesNotMatch(text(render()), /previous result|worker is checking/);
});

test("enterprise API refusals keep their specific reason instead of generic HTTP text", () => {
  const { reasonText } = load("@/console/views/integrations/github-enterprise.tsx", { extraExports: "\nexport { reasonText };" });
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  for (const [code, status, expected] of [
    ["GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE", 409, /Start collecting first/],
    ["GITHUB_ENTERPRISE_QUEUE_FULL", 409, /1,000 organizations/],
    ["GITHUB_ENTERPRISE_SEALED_CREDENTIAL_REQUIRED", 422, /not a Vault reference/],
  ]) assert.match(reasonText(new DashboardAPIError(code, status), (_ko, en) => en), expected);
});
