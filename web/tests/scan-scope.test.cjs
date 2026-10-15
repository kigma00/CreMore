// The scan scope model the console's integrations screen uses (lib/scan-scope.ts): a connection's catalog is checked as
// it arrives, and a new scope starts empty and bounded. Synthetic data only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const scope = load("@/lib/scan-scope.ts");
const connection = { kind: "source", connection_id: "synthetic-connection", provider: "github", display_name: "Synthetic connection" };
const resource = (id, changes = {}) => ({ id, provider_resource_id: `provider-${id}`, provider_instance_id: "https://api.github.com", resource_type: "GITHUB_REPOSITORY", display_name: "Same display name", canonical_reference: `example/${id}`, list_visibility: "VISIBLE", content_readiness: "NEEDS_RUNTIME_CHECK", visibility: "PRIVATE", default_branch: "main", ...changes });
const catalog = (items = [resource("a")], changes = {}) => ({ ...connection, items, catalog_snapshot_id: "synthetic-snapshot", auth_revision: "synthetic-auth", catalog_completeness: "PARTIAL", last_refreshed_at: "2026-09-10T00:00:00Z", known_count: items.length, count_accuracy: "KNOWN_ONLY", has_more: false, available_filters: ["visibility", "archived"], ...changes });
const normalize = value => JSON.parse(JSON.stringify(value));

test("new scope has zero targets, disabled automation and bounded defaults", () => {
  const input = scope.defaultScopeInput();
  assert.equal(input.selected_roots.length, 0); assert.equal(input.excluded_ids.length, 0);
  assert.equal(input.expected_version, 0); assert.equal(input.schedule_minutes, 0); assert.equal(input.event_mode, "DISABLED");
  assert.deepEqual(normalize(input.budgets), { bytes: 536870912000, requests: 2000000, seconds: 21600 });
  assert.notEqual(scope.defaultScopeInput(), input, "each scope starts from its own copy");
});

test("catalog rejects cross-connection identity, duplicate IDs and malformed pagination", () => {
  assert.equal(scope.projectScopeCatalog(catalog(), connection).items.length, 1);
  for (const bad of [catalog([], { connection_id: "other" }), catalog([], { kind: "aws" }), catalog([resource("a"), resource("a")]), catalog([], { has_more: true }),
    catalog([], { known_count: -1 }), catalog([{ ...resource("a"), content_readiness: undefined }]), catalog(Array.from({ length: 201 }, (_, index) => resource(`r${index}`)))]) {
    assert.throws(() => scope.projectScopeCatalog(bad, connection), /SCOPE_RESPONSE/);
  }
  const empty = scope.projectScopeCatalog(catalog([], { items: null, known_count: 0, available_filters: null }), connection);
  assert.equal(empty.items.length, 0); assert.equal(empty.available_filters.length, 0);
  assert.equal(scope.projectScopeCatalog(catalog([], { has_more: true, next_cursor: "opaque" }), connection).next_cursor, "opaque");
});

test("metadata projections preserve known-empty topics and reject malformed capabilities", () => {
  assert.deepEqual(normalize(scope.projectScopeCatalog(catalog([resource("a", { topics: [] })]), connection).items[0].topics), []);
  for (const changes of [{ topics: "bad" }, { known_root_ids: "bad" }, { last_scan_at: "yesterday" }, { subtree_expansion_allowed: "true" }]) {
    assert.throws(() => scope.projectScopeCatalog(catalog([resource("a", changes)]), connection), /SCOPE_RESPONSE_INVALID/);
  }
  assert.throws(() => scope.projectScopeCatalog(catalog([], { metadata_search_enabled: "true" }), connection), /SCOPE_RESPONSE_INVALID/);
});
