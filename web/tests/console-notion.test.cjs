const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const model = load("@/console/views/integrations/model.ts");
const plain = value => JSON.parse(JSON.stringify(value));

test("Notion PAT and MCP choices count only their own permissions, including saved PAT-only plans", () => {
  const d = { provider: "notion", purposes: { inventory: {
    types: [{ id: "personal_access_token", plan: [{ field: "personal_access_tokens" }] },
      { id: "mcp_connection", plan: [{ field: "mcp_connections" }] }],
    plan: [{ name: "personal_access_tokens", kind: "bool", default: true },
      { name: "mcp_connections", kind: "bool", default: false }],
    permissions: [{ id: "workspace_tokens", option: "personal_access_tokens" },
      { id: "mcp_connections", option: "mcp_connections" }] } } };
  const fields = model.planFields(d, "inventory", "cloud", {}, true);
  let values = model.valuesOf(fields, {});
  const choices = () => model.typeChoices(d, "cloud", {}, fields, values);
  assert.deepEqual(plain(choices().map(c => [c.type.id, c.on])), [["personal_access_token", true], ["mcp_connection", false]]);
  values = model.switchType(choices()[1], values, true);
  values = model.switchType(choices()[0], values, false);
  assert.deepEqual(plain(values), { personal_access_tokens: false, mcp_connections: true });
  assert.deepEqual(plain(model.permissionsFor(d, "inventory", "organization_bot", {}, values).map(p => p.id)), ["mcp_connections"]);
  const connection = { edition: "cloud", target: {}, purposes: ["inventory"], plans: { inventory: values }, checks: {
    results: { inventory: { items: [{ permission: "workspace_tokens", status: "MISSING" }, { permission: "mcp_connections", status: "GRANTED" }] } } } };
  assert.equal(model.checkSummary(model.checkItems(connection, ["inventory"], d)), "ok");
  connection.plans.inventory = {}; // Legacy plans still require PAT, never MCP.
  assert.deepEqual(plain(model.checkItems(connection, ["inventory"], d).map(p => p.permission)), ["workspace_tokens"]);
});
