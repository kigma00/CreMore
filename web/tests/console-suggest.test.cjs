// A service the company IdP already lists: the suggestion says which IdP apps it came from.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const ko = (text, _en) => text;
const en = (_ko, text) => text;

test("a suggestion names a few of the IdP apps it came from", () => {
  const item = { provider: "atlassian", apps: ["Atlassian Cloud", "Jira Service Management"], count: 2 };
  assert.equal(model.suggestionText(item, ko), "회사 IdP의 앱: Atlassian Cloud, Jira Service Management");
  assert.equal(model.suggestionText({ ...item, count: 5 }, ko), "회사 IdP의 앱: Atlassian Cloud, Jira Service Management 외 3개");
  assert.equal(model.suggestionText({ ...item, count: 5 }, en), "Company IdP apps: Atlassian Cloud, Jira Service Management and 3 more");
  assert.equal(model.SUGGESTIONS_PATH, "provider-connections/suggestions");
});
