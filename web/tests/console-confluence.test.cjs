// Confluence Cloud as a service account in the console: the setup steps name the OAuth scopes the method
// checks, and what the check and a scan can answer reads as words. Synthetic descriptor only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const guide = load("@/console/views/integrations/guide.tsx");
const copy = load("@/console/views/integrations/copy.ts");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));

const SCOPES = ["read:space:confluence", "read:page:confluence", "read:attachment:confluence", "read:content-details:confluence"];
const CONFLUENCE = {
  provider: "confluence", label: "Confluence", label_ko: "Confluence", category: "saas", target: [],
  editions: [{ id: "cloud", label: "Confluence Cloud", label_ko: "Confluence Cloud" }],
  purposes: { exposure: { permissions: [
    { id: "read_space", label: "Read the space", label_ko: "공간 읽기", methods: ["token"] },
    ...SCOPES.map(id => ({ id, label: id, label_ko: id, methods: ["service_account"] })),
  ] } },
  auth_methods: [
    { id: "service_account", label: "Service account (OAuth 2.0)", label_ko: "서비스 계정(OAuth 2.0)", renewal: "AUTOMATIC",
      editions: ["cloud"], purposes: ["exposure"], reference: false, fields: [] },
    { id: "token", label: "API token", label_ko: "API 토큰", renewal: "EXPIRES", purposes: ["exposure"], fields: [] },
  ],
};

test("the service account's steps end with the scopes its check asks about", () => {
  const steps = guide.guideSteps(CONFLUENCE, CONFLUENCE.auth_methods[0], null, {}, L);
  assert.deepEqual(plain(steps.map(step => step.key)), ["account", "space", "oauth"]);
  assert.equal(steps[0].actions[0].href, "https://admin.atlassian.com");
  assert.equal(steps[2].actions[0].text, SCOPES.join("\n"));
  assert.equal(guide.guideSteps(CONFLUENCE, CONFLUENCE.auth_methods[1], null, {}, L).length, 0);
});

test("the methods say where their token goes and what the check found", () => {
  assert.match(copy.methodHint("confluence", CONFLUENCE.auth_methods[0], L), /api\.atlassian\.com\)에만 보냅니다/);
  assert.match(copy.methodHint("confluence", CONFLUENCE.auth_methods[1], L), /ex\/confluence\/<Cloud ID>\/wiki/);
  assert.equal(copy.renewalTag(CONFLUENCE.auth_methods[0], L).text, "자동 갱신");
  assert.equal(model.detailText("CONFLUENCE_SPACE_NOT_VISIBLE", L), "공간이 없거나 서비스 계정에 보기 권한이 없음");
  assert.match(model.detailText("ATLASSIAN_OAUTH_TOKEN_REFUSED", L), /클라이언트 ID·시크릿 확인/);
  assert.match(model.detailText("ATLASSIAN_OAUTH_UNAVAILABLE", L), /잠시 뒤 다시 확인/);
  assert.match(model.onboardingText("ATLASSIAN_OAUTH_CLIENT_INVALID", [], L), /Atlassian 관리에서 복사한 그대로/);
});
