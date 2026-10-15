"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const ID = "00000000-0000-4000-8000-000000000001";
const pending = { status: "QUEUED", request_id: ID, poll_url: `/api/v1/aws/requests/${ID}` };
const response = (status, body, headers) => new Response(JSON.stringify(body), { status, headers });

function client(answer, timers = {}) {
  const calls = [];
  const api = load("@/lib/dashboard-api.ts", { globals: {
    fetch: async (path, init) => { calls.push({ path, ...init }); return answer(calls.length, path, init); },
    setTimeout: callback => { queueMicrotask(callback); return 1; }, clearTimeout() {}, ...timers,
  } });
  return { ...api, calls };
}

test("a queued mutation is sent once and its pending reads preserve the final page", async () => {
  const c = client(n => n < 3 ? response(202, pending) : response(200, [{ name: "synthetic" }], {
    "X-Next-Cursor": "cursor", "X-Page-Limit": "20",
  }));
  const body = JSON.stringify({ source: "org" });
  assert.deepEqual(await c.api("aws/accounts/discover", { method: "POST", body }), [{ name: "synthetic" }]);
  assert.deepEqual(c.calls.map(call => [call.path, call.method || "GET", call.body]), [
    ["/api/backend/aws/accounts/discover", "POST", body],
    [`/api/backend/aws/requests/${ID}`, "GET", undefined], [`/api/backend/aws/requests/${ID}`, "GET", undefined],
  ]);
  const page = client(n => n === 1 ? response(202, pending) : response(200, [1], { "X-Next-Cursor": "next", "X-Page-Limit": "3" }));
  assert.deepEqual(JSON.parse(JSON.stringify(await page.apiPage("aws/secrets-inventory"))), { data: [1], nextCursor: "next", pageLimit: 3 });
});

test("a pending request has a finite polling budget without resubmitting its mutation", async () => {
  const c = client(() => response(202, pending));
  await assert.rejects(c.api("aws/accounts/discover", { method: "POST" }), error => error.status === 409 && /AWS_READ_PENDING/.test(error.message));
  assert.equal(c.calls.length, 121);
  assert.equal(c.calls.filter(call => call.method === "POST").length, 1);
});

test("poll errors and transport failures propagate without retrying a mutation", async () => {
  for (const failure of [() => response(409, { error: "AWS_REQUEST_SCOPE_CHANGED" }), () => { throw new Error("lost response"); }]) {
    const c = client(n => n === 1 ? response(202, pending) : failure());
    await assert.rejects(c.api("aws/accounts/discover", { method: "POST" }), /AWS_REQUEST_SCOPE_CHANGED|lost response/);
    assert.equal(c.calls.length, 2);
  }
  const c = client(() => { throw new Error("initial response lost"); });
  await assert.rejects(c.api("aws/accounts/discover", { method: "POST" }), /initial response lost/);
  assert.equal(c.calls.length, 1);
});

test("only the exact local AWS request path with a UUID can be followed", async () => {
  for (const data of [
    { ...pending, poll_url: "https://outside.example/request" },
    { ...pending, poll_url: `//outside.example/api/v1/aws/requests/${ID}` },
    { ...pending, poll_url: `/api/v1/aws/requests/${ID}?next=outside` },
    { ...pending, request_id: "-".repeat(36), poll_url: "/api/v1/aws/requests/" + "-".repeat(36) },
    { status: "QUEUED", job_id: ID },
  ]) {
    const c = client(() => response(202, data));
    assert.deepEqual(await c.api("local-operation"), data);
    assert.equal(c.calls.length, 1);
  }
});

test("aborting a pending wait clears its timer and sends no poll or repeat mutation", async () => {
  const controller = new AbortController();
  let waiting, cleared = false;
  const c = client(() => response(202, pending), { setTimeout: callback => { waiting = callback; return 23; },
    clearTimeout: id => { assert.equal(id, 23); cleared = true; } });
  const result = c.api("aws/accounts/discover", { method: "POST", signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(typeof waiting, "function");
  const reason = new Error("view closed");
  controller.abort(reason);
  await assert.rejects(result, error => error === reason);
  assert.equal(cleared, true);
  assert.equal(c.calls.length, 1);
});
