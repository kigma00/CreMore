// The console's secret stores: which records are stores, why "not in a store" waits, and the body a
// storage record sends. Synthetic connections only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const vaults = load("@/console/views/vaults/page.tsx");
const receipts = load("@/console/views/vaults/receipts.tsx");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));

test("a store is a provider connection's record for the vault purpose, with its own health", () => {
  const conns = [
    { id: "p1", provider: "aws", name: "AWS", plans: { vault: {}, inventory: {} }, children: [
      { kind: "coverage", id: "c1", purpose: "vault" }, { kind: "coverage", id: "c2", purpose: "inventory" }] },
    { id: "p2", provider: "gitlab", name: "GitLab", plans: { vault: {} }, children: [{ kind: "metadata", id: "m1", purpose: "vault" }] },
    { id: "p3", provider: "github", name: "GitHub", plans: { inventory: {} }, children: [{ kind: "metadata", id: "m2", purpose: "vault" }] },
  ];
  const health = [{ key: "coverage:c1", name: "Secrets Manager 1" }, { key: "coverage:m1", name: "CI variables" }];
  const stores = vaults.storesOf(conns, health);
  assert.deepEqual(plain(stores.map(store => [store.conn.id, store.child.id, store.health?.name ?? null])),
    [["p1", "c1", "Secrets Manager 1"], ["p2", "m1", "CI variables"]]);
});

test("why 'not in a store' waits reads as words", () => {
  assert.equal(vaults.reasonWords("VAULT_SCOPE_NOT_CONFIRMED", L), "저장소 목록이 전부라고 아직 확정하지 않았습니다");
  assert.equal(vaults.reasonWords("NEVER_COLLECTED", L), "아직 한 번도 수집하지 않은 저장소가 있습니다");
  assert.equal(vaults.reasonWords("SOMETHING_NEW", L), "Something New");
});

test("a storage record sends the two collected anchors and the source record, trimmed", () => {
  const anchor = (run) => ({ anchor: { run_id: run, batch_index: 0, item_index: 2 }, connection_id: "c", connection_name: "n", provider: "p", reference: "r", version: "" });
  const body = receipts.receiptBody(anchor("r1"), anchor("r2"), { system: " vault-rotation ", record: " rotation/1 ", stored: "2026-09-27T10:30:00Z" });
  assert.deepEqual(plain(body), { issuer: { run_id: "r1", batch_index: 0, item_index: 2 }, vault: { run_id: "r2", batch_index: 0, item_index: 2 },
    source_system: "vault-rotation", source_record_id: "rotation/1", stored_at: "2026-09-27T10:30:00.000Z" });
});
