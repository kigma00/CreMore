// The console's collection and detection logs: what a run is, which integration owns it and what it
// read, from synthetic runs and connections.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const logs = load("@/console/views/logs.tsx");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));

const run = (changes = {}) => ({ id: "r1", status: "SUCCEEDED", kind: "scope", mode: "BASELINE", trigger_type: "MANUAL", connection_id: "s1",
  resources_succeeded: 12, resources_failed: 0, findings_total: 0, duration_seconds: 3.2, error: null,
  created_at: "2026-09-27T01:00:00Z", started_at: "2026-09-27T01:00:01Z", completed_at: "2026-09-27T01:00:04Z", ...changes });

test("a run's kind and state read as the screen groups them", () => {
  assert.equal(logs.kindOf("scope").group, "scan");
  assert.equal(logs.kindOf("github").group, "scan");
  assert.equal(logs.kindOf("provider-metadata-inventory").group, "collect");
  assert.equal(logs.kindOf("credential-usage").group, "collect");
  assert.equal(logs.kindOf("credential-usage").name[0], "AWS 사용 기록 수집");
  assert.equal(logs.stopPath(run({ kind: "credential-usage", status: "RUNNING" })), "source-scan-jobs/r1/cancel");
  assert.equal(logs.kindOf("provider-check").group, "check");
  assert.equal(logs.kindOf("catalog-refresh").group, "catalog");
  assert.deepEqual(["QUEUED", "RUNNING", "CANCELLING", "SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED", "ODD"].map(logs.stateOf),
    ["queued", "running", "running", "done", "partial", "failed", "cancelled", "queued"]);
});

test("a run belongs to the integration that owns its record, or the one its check was for", () => {
  const conn = { id: "p1", provider: "gitlab", name: "GitLab · group", children: [{ kind: "content", id: "s1", purpose: "exposure", name: "GitLab · group" },
    { kind: "metadata", id: "m1", purpose: "inventory", name: null }] };
  const map = logs.owners([conn]);
  assert.equal(logs.ownerOf(run(), map).conn.id, "p1");
  assert.equal(logs.ownerOf(run({ kind: "provider-metadata-inventory", connection_id: "m1" }), map).conn.id, "p1");
  assert.equal(logs.ownerOf(run({ kind: "provider-check", connection_id: null, provider_connection_id: "p1" }), map).conn.id, "p1");
  assert.equal(logs.ownerOf(run({ kind: "provider-metadata-inventory", connection_id: null, coverage_connection_id: "m1" }), map).conn.id, "p1");
  assert.equal(logs.ownerOf(run({ connection_id: "elsewhere" }), map), undefined);
});

test("what a run read and found reads in a few words", () => {
  assert.equal(logs.resultOf(run({ findings_total: 2, resources_failed: 1 }), L), "읽은 곳 12 · 새 노출 2 · 실패 1");
  assert.equal(logs.resultOf(run({ status: "QUEUED" }), L), "—");
  assert.equal(logs.resultOf(run({ kind: "provider-metadata-inventory", status: "FAILED", resources_succeeded: 0, error: "HTTP_403" }), L), "—");
  assert.deepEqual(plain(logs.uploadedRun({ id: "u1", status: "PARTIAL", reasons: ["PAGE_LIMIT"], item_count: 9, started_at: "2026-09-27T01:00:00Z",
    finished_at: "2026-09-27T01:00:30Z" }, "c9")), { id: "u1", status: "PARTIAL", kind: "customer-collection", connection_id: "c9", resources_succeeded: 9,
    resources_failed: 0, findings_total: 0, duration_seconds: 30, error: "PAGE_LIMIT", created_at: "2026-09-27T01:00:00Z", started_at: "2026-09-27T01:00:00Z",
    completed_at: "2026-09-27T01:00:30Z" });
  assert.equal(logs.uploadedRun({ id: "u2", status: "RUNNING", item_count: 0, started_at: "2026-09-27T01:00:00Z", finished_at: null }, "c9").status, "RUNNING");
  assert.equal(logs.resultOf(run({ kind: "catalog-refresh", resources_succeeded: 7 }), L), "7곳 확인");
  assert.equal(logs.resultOf(run({ kind: "provider-metadata-inventory", resources_succeeded: 30 }), L), "메타데이터 수 미확인");
  assert.equal(logs.resultOf(run({ kind: "provider-check", error: "HTTP_403" }), L), "확인하지 못함");
  assert.equal(logs.resultOf(run({ kind: "provider-check" }), L), "확인함");
  assert.deepEqual(plain(Object.keys(logs.kindOf("inline"))), ["group", "name"]);
});

test("metadata collection counts committed records rather than content objects or people", () => {
  const metadata = run({ kind: "provider-metadata-inventory", resources_succeeded: 0,
    metadata_items: 9, count_basis: "COMMITTED_METADATA_RECORDS" });
  for (const status of ["SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"]) {
    assert.equal(logs.resultOf({ ...metadata, status }, L), "메타데이터 9개");
    assert.equal(logs.resultOf({ ...metadata, status }, (_ko, en) => en), "9 metadata records");
  }
  assert.equal(logs.resultOf({ ...metadata, status: "QUEUED" }, L), "—");
  assert.equal(logs.resultOf({ ...metadata, metadata_items: 0 }, L), "메타데이터 0개");
  for (const value of [undefined, null, -1, 1.5, "9", Infinity]) {
    assert.equal(logs.resultOf({ ...metadata, metadata_items: value }, L), "메타데이터 수 미확인");
  }
  assert.equal(logs.resultOf({ ...metadata, count_basis: undefined }, L), "메타데이터 수 미확인");
  assert.equal(logs.resultOf({ ...metadata, count_basis: "COMMITTED_OBJECT_ATTEMPTS" }, L), "메타데이터 수 미확인");
  assert.equal(logs.resultOf({ ...metadata, kind: "scope", resources_succeeded: 12 }, L), "읽은 곳 12");
  assert.equal(logs.resultOf({ ...metadata, kind: "aws-credential-inventory", resources_succeeded: 12 }, L), "항목 12개");
  const uploaded = logs.uploadedRun({ id: "u1", status: "COMPLETE", item_count: 9,
    started_at: metadata.started_at, finished_at: metadata.completed_at }, "m1", true);
  assert.equal(logs.resultOf(uploaded, L), "메타데이터 9개");
});

test("a change run partial only for the upgrade hold is not counted as failed and says why it was not read whole", () => {
  const { failureCodeLabel } = load("@/components/labels.tsx");
  const en = (_ko, en) => en;
  // As GET /api/v1/scan-runs serves them (cremore/api/source_presenters.py present_scan_run).
  const held = run({ status: "PARTIAL", mode: "DELTA", trigger_type: "SCHEDULE", policy_held_roots: 1, policy_held_only: true });
  const heldAndGap = run({ status: "PARTIAL", mode: "DELTA", policy_held_roots: 1 });
  const heldAndStop = { ...heldAndGap, error: "BUDGET_BYTES" };
  const partial = run({ status: "PARTIAL" });
  assert.deepEqual([held, heldAndGap, heldAndStop, partial, run({ status: "FAILED" }), run()].map(logs.troubled),
    [false, true, true, true, true, false]);
  // The held run says why, in either language; anything else partial keeps the note it had.
  assert.ok(logs.rowNote(held, L, "ko") && logs.rowNote(held, en, "en") && logs.rowNote(held, L, "ko") !== logs.rowNote(held, en, "en"));
  assert.equal(logs.rowNote(heldAndGap, L, "ko"), null);
  assert.equal(logs.rowNote(partial, L, "ko"), null);
  // A held-only run that also carries an error code: the error is named, not the hold.
  assert.ok(logs.rowNote(held, L, "ko") !== failureCodeLabel("BUDGET_BYTES", "ko"));
  assert.equal(logs.rowNote({ ...held, error: "BUDGET_BYTES" }, L, "ko"), failureCodeLabel("BUDGET_BYTES", "ko"));
  assert.equal(logs.rowNote(heldAndStop, L, "ko"), failureCodeLabel("BUDGET_BYTES", "ko"));
  // A completed run is never held, whatever it carries.
  assert.equal(logs.rowNote(run({ policy_held_only: true }), L, "ko"), null);
});
