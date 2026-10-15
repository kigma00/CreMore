"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const L = (ko) => ko;
// A run as GET /api/v1/scan-runs serves it (cremore/api/source_presenters.py present_scan_run).
const run = (fields) => ({ id: "j1", status: "RUNNING", kind: "provider-metadata-inventory", connection_id: null, coverage_connection_id: "c1",
  resources_succeeded: 0, resources_failed: 0, findings_total: 0, duration_seconds: null, error: null, created_at: "2026-09-30T00:00:00Z",
  started_at: null, completed_at: null, ...fields });
// An operation report as GET /api/v2/coverage/runs/{id}?record_type=operation_report serves its body
// (cremore/coverage/metadata_models.py OperationReport).
const report = (fields) => ({ status: "COMPLETE", reasons: [], pages: 1, received_records: 12, saved_records: 12, expected_records: null,
  scope: { kind: "organization", id: "acme" }, provenance: { operation: "github.fine_grained_pats", resource_id: "/orgs/acme/personal-access-tokens" }, ...fields });

test("a run is stopped the way its job can be: a collection through itself, a content scan while it runs, other jobs while queued", () => {
  const logs = load("@/console/views/logs.tsx");
  assert.equal(logs.collectionOf(run({})), "c1");
  assert.equal(logs.collectionOf(run({ kind: "aws-credential-inventory" })), null);
  assert.equal(logs.stopPath(run({})), "v2/coverage/connections/c1/collect/stop");
  assert.equal(logs.stopPath(run({ status: "QUEUED" })), "v2/coverage/connections/c1/collect/stop");
  assert.equal(logs.stopPath(run({ status: "CANCELLING" })), null);
  assert.equal(logs.stopPath(run({ status: "SUCCEEDED" })), null);
  assert.equal(logs.stopPath(run({ kind: "scope", coverage_connection_id: undefined })), "scan-runs/j1/cancel");
  assert.equal(logs.stopPath(run({ kind: "inline", coverage_connection_id: undefined })), "source-scan-jobs/j1/cancel");
  // A schema 1 inventory or a check is withdrawn only while queued: the job cancel cannot stop it running.
  assert.equal(logs.stopPath(run({ kind: "aws-credential-inventory", coverage_connection_id: undefined })), null);
  assert.equal(logs.stopPath(run({ kind: "aws-credential-inventory", coverage_connection_id: undefined, status: "QUEUED" })), "source-scan-jobs/j1/cancel");
  assert.equal(logs.stopPath(run({ kind: "provider-check", coverage_connection_id: undefined })), null);
  assert.equal(logs.stopPath(run({ kind: "github-secret-scanning", coverage_connection_id: undefined })), null);
  assert.equal(logs.stopPath(run({ kind: "aws-role-check", coverage_connection_id: undefined })), null);
  assert.equal(logs.stopPath(run({ kind: "github-org", coverage_connection_id: undefined })), "source-scan-jobs/j1/cancel");
  assert.equal(logs.kindOf("aws-role-check").group, "check");
  // An approved plan's run is withdrawn by cancelling the plan, never here; nor is a customer-side upload, which is not a job.
  assert.equal(logs.stopPath(run({ kind: "provider-credential-action", coverage_connection_id: undefined, status: "QUEUED" })), null);
  assert.equal(logs.stopPath(run({ kind: "customer-collection", coverage_connection_id: undefined })), null);
});

test("a finished, stopped or failed collection reports what it read; one still running does not yet", () => {
  const logs = load("@/console/views/logs.tsx");
  for (const status of ["SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"]) assert.deepEqual([...logs.reportRuns(run({ status, coverage_run_ids: ["r1"] }))], ["r1"], status);
  assert.equal(logs.reportRuns(run({ coverage_run_ids: ["r1"] })).length, 0);
  assert.equal(logs.reportRuns(run({ status: "SUCCEEDED" })).length, 0);
  // An uploaded metadata run is its own stored run; a schema 1 upload or one still open names none.
  const stored = { id: "11111111-1111-4111-8111-111111111111", status: "COMPLETE", item_count: 3, started_at: "2026-09-30T00:00:00Z", finished_at: "2026-09-30T00:05:00Z" };
  assert.deepEqual([...logs.uploadedRun(stored, "child", true).coverage_run_ids], [stored.id]);
  assert.equal(logs.uploadedRun(stored, "child").coverage_run_ids, undefined);
  assert.equal(logs.uploadedRun({ ...stored, finished_at: null }, "child", true).coverage_run_ids, undefined);
});

test("the report says what each read did, took in and why it stopped short, with the code kept", () => {
  const logs = load("@/console/views/logs.tsx");
  assert.deepEqual([...logs.reportStatus("PARTIAL", L)], ["일부 완료", "partial"]);
  assert.deepEqual([...logs.reportStatus("SOMETHING_NEW", L)], ["SOMETHING_NEW", undefined]);
  assert.equal(logs.reportCounts(report({ received_records: 40, saved_records: 38, expected_records: 50 }), L), "받음 40 · 저장 38 · 예상 50");
  const locale = load("@/components/locale.tsx");
  const list = (props) => renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" }, React.createElement(logs.ReportList, props)));
  const markup = list({ total: 3, items: [{ id: "1", body: report({}) }, { id: "2", body: report({ status: "PARTIAL", received_records: 5, saved_records: 5,
    reasons: ["GITHUB_RATE_LIMITED"], provenance: { operation: "github.org_audit", resource_id: null } }) }] });
  assert.match(markup, /github\.fine_grained_pats[\s\S]*완료[\s\S]*받음 12 · 저장 12/);
  assert.match(markup, /github\.org_audit[\s\S]*일부 완료[\s\S]*GitHub 요청 한도 · 기다렸다가 이어감 \(GITHUB_RATE_LIMITED\)/);
  assert.match(markup, /외 1건/);
  assert.match(list({ total: 0, items: [] }), /수집 보고를 남기지 않았습니다/);
});

test("the run panel acts only for an Analyst, on the collection's current job, with its pause as the server holds it", () => {
  const module = load("@/console/views/logs.tsx");
  const live = (job) => ({ id: "c1", collection_paused: false, latest_job: job ? { id: job } : null });
  assert.equal(module.controls(run({}), live("j1")), true);
  assert.equal(module.controls(run({ status: "QUEUED" }), live("j1")), true);
  // A newer job of the same collection, a run that finished while the panel kept the list it last read, or one stopping:
  // the controls would act on another job, or on none.
  assert.equal(module.controls(run({}), live("j2")), false);
  assert.equal(module.controls(run({ status: "SUCCEEDED" }), live("j1")), false);
  assert.equal(module.controls(run({ status: "CANCELLING" }), live("j1")), false);
  assert.equal(module.controls(run({}), undefined), false);
  const logs = source("@/console/views/logs.tsx");
  assert.match(logs, /canAct=\{hasRole\(session\.role, "Analyst"\)\}/);
  // The pause is the server's word (GET v2/coverage/connections collection_paused), for the job it is about.
  assert.match(logs, /useApi<\{ items: LiveCollection\[\] \}>\(collection && active && canAct \? "v2\/coverage\/connections" : null, \{ every: 5_000 \}\)/);
  assert.match(logs, /const controllable = controls\(run, current\)/);
  assert.match(logs, /const paused = Boolean\(current\?\.collection_paused\)/);
  assert.match(logs, /\{canAct && controllable \? <button/);
  assert.match(logs, /canAct && stop && \(!collection \|\| controllable\)/);
  assert.match(logs, /\{canAct && again && !active \?/);
  // An access check is run again by an Admin (POST provider-connections/{id}/check).
  assert.match(logs, /run\.kind === "provider-check" && run\.provider_connection_id && admin \?/);
  // A people directory's runs are an Analyst's to read, and none has a native export; a run past its retention is gone.
  assert.match(logs, /const reports = !canAct && \(!child \|\| people\) \? \[\] : reportRuns\(run\)/);
  assert.match(logs, /<RunReport key=\{id\} runId=\{id\} exportable=\{!people\} \/>/);
  assert.match(logs, /view\.error instanceof DashboardAPIError && view\.error\.status === 404/);
  assert.match(logs, /downloadJson\(`cremore-collection-\$\{runId\}\.json`, await api<unknown>\(`v2\/coverage\/runs\/\$\{runId\}\/export\?format=native`\)\)/);
  // An operator's pause reads as one; the refusals read in words.
  assert.equal(load("@/components/labels.tsx").holdText("METADATA_COLLECTION_PAUSED", "ko").title, "운영자가 일시 정지함");
  const data = load("@/console/data.ts");
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  assert.match(data.reasonText(new DashboardAPIError("NATIVE_EXPORT_UNSUPPORTED", 409), L), /원본 형식으로 내보내지 않습니다/);
  assert.match(data.reasonText(new DashboardAPIError("NATIVE_EXPORT_LIMIT_USE_RECORD_PAGES", 409), L), /기록이 너무 많아/);
  assert.match(data.reasonText(new DashboardAPIError("METADATA_COLLECTION_NOT_RUNNING", 409), L), /진행 중이 아닙니다/);
});

test("collection outcomes and retries belong to each profile, and paused features stay paused", async () => {
  const calls = [];
  let deny = true, readFails = false;
  const { collectConnection } = load("@/console/views/integrations/collect.tsx", { overrides: {
    "@/console/data": { send: async (path, method, body) => {
      calls.push(path === "scan-runs" ? body.plan_id : path);
      if (path.endsWith("/preview")) return { executable: true, plan_id: path.split("/")[1] };
      if (deny && body?.plan_id === "second") throw new Error("SCAN_BUSY");
      return { id: body?.plan_id ?? "metadata-job" };
    } },
    "@/console/views/integrations/scope": {
      scopeTargets: () => [{ id: "source", name: "Source" }],
      readProfiles: async () => {
        if (readFails) throw new Error("READ_FAILED");
        return { profiles: ["first", "second"].map(id => ({ id, name: id, version: 2, selected_roots: [{}] })) };
      },
    },
  } });
  const c = { plans: { exposure: {} }, children: [{ kind: "metadata", id: "paused", purpose: "identity" }], feature_enabled: { identity: false } };
  const first = await collectConnection(c);
  assert.equal(first.length, 2);
  assert.equal(first[0].jobId, "first");
  assert.equal(first[1].error, "SCAN_BUSY");
  deny = false; calls.length = 0;
  const second = await collectConnection(c, new Set(first.filter(r => r.error).map(r => r.key)));
  assert.equal(second.length, 1); assert.equal(second[0].jobId, "second");
  assert.deepEqual(calls, ["scan-scope-profiles/second/preview", "second"]);
  readFails = true;
  assert.equal((await collectConnection(c))[0].error, "READ_FAILED");
  readFails = false;
  assert.equal((await collectConnection(c, new Set(["exposure:source"]))).length, 2);
  calls.length = 0;
  assert.equal((await collectConnection({ ...c, feature_enabled: { identity: false, exposure: false } })).length, 0);
  assert.equal(calls.length, 0);
});
