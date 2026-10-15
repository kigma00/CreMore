const test = require("node:test");
const { source: readSource } = require("./load-module.cjs");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("typescript");
const code = ts.transpileModule(readSource("@/app/api/backend/[...path]/route.ts"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
function setup(mode, env = {}, reply = () => Response.json({ ok: true })) {
  const calls = [];
  const loaded = { exports: {} };
  vm.runInNewContext(code, { module: loaded, exports: loaded.exports, require: () => ({ NextResponse: Response }), URL, Headers, TextDecoder, Uint8Array, process: { env: { CREMORE_API_URL: "http://127.0.0.1:3302", CREMORE_AUTH_MODE: mode, CREMORE_API_TOKEN: "synthetic-server-only", ...env } }, fetch: async (url, options) => { calls.push({ url, options }); return reply(); } });
  return { api: loaded.exports, calls };
}
function request(origin, mode = "local") {
  const value = new Request("http://localhost:3301/api/backend/action-plans/demo/cancel", { method: "POST", headers: { host: "localhost:3301", ...(origin ? { origin } : {}), ...(mode === "oidc" ? { authorization: "Bearer synthetic-oidc" } : {}) }, body: "{}" });
  value.nextUrl = new URL(value.url);
  return value;
}
const context = { params: Promise.resolve({ path: ["action-plans", "demo", "cancel"] }) };
test("both local and OIDC mutations enforce same origin before forwarding", async () => {
  for (const mode of ["local", "oidc"]) {
    const { api, calls } = setup(mode);
    for (const origin of [undefined, "https://unrelated.example"]) assert.equal((await api.POST(request(origin, mode), context)).status, 403);
    assert.equal(calls.length, 0);
    const response = await api.POST(request("http://localhost:3301", mode), context);
    assert.equal(response.status, 200); assert.equal(calls.length, 1);
    assert.equal(calls[0].options.redirect, "error"); assert.equal(calls[0].options.cache, "no-store");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer"); assert.equal(response.headers.get("cache-control"), "no-store");
    assert.doesNotMatch(await response.text(), /synthetic-server-only|synthetic-oidc/);
  }
});

function mutation(method, segments, body, headers = {}) {
  const value = new Request(`http://localhost:3301/api/backend/${segments.join("/")}`, { method, headers: { host: "localhost:3301", origin: "http://localhost:3301", ...headers }, body, ...(body instanceof ReadableStream ? { duplex: "half" } : {}) });
  value.nextUrl = new URL(value.url);
  return { value, context: { params: Promise.resolve({ path: segments }) } };
}
test("a delete the API answers with 204 reaches the browser as 204, not as an unavailable API", async () => {
  const { api, calls } = setup("local", {}, () => new Response(null, { status: 204 }));
  const { value, context } = mutation("DELETE", ["rules", "synthetic-rule"]);
  const response = await api.DELETE(value, context);
  assert.equal(response.status, 204); assert.equal(calls.length, 1); assert.equal(calls[0].options.method, "DELETE");
  assert.equal(await response.text(), "");
});
test("upstream response streams without buffering and preserves pagination headers", async () => {
  let finish;
  const stream = new ReadableStream({ start(controller) {
    controller.enqueue(new TextEncoder().encode("["));
    finish = () => { controller.enqueue(new TextEncoder().encode("]")); controller.close(); };
  } });
  const upstream = new Response(stream, { headers: { "X-Next-Cursor": "next-page", "X-Page-Limit": "200" } });
  upstream.text = () => { throw new Error("must not buffer upstream"); };
  const { api } = setup("local", {}, () => upstream);
  const response = await api.POST(request("http://localhost:3301"), context);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-next-cursor"), "next-page");
  assert.equal(response.headers.get("x-page-limit"), "200");
  finish();
  assert.equal(await response.text(), "[]");
});
test("PATCH forwards saved profile edits with the scope write limit", async () => {
  const { api, calls } = setup("local");
  const body = JSON.stringify({ selected_roots: "x".repeat(1024 * 1024), name: "합성 범위" });
  const { value, context } = mutation("PATCH", ["scan-scope-profiles", "synthetic-profile"], body);
  assert.equal((await api.PATCH(value, context)).status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, "PATCH");
  assert.equal(calls[0].options.body, body);
  assert.equal(calls[0].options.headers.get("authorization"), "Bearer synthetic-server-only");
});
test("ordinary mutations reject streamed bodies over 1 MiB even with an understated length", async () => {
  for (const headers of [{}, { "content-length": "2" }]) {
    const { api, calls } = setup("local");
    let cancelled = false;
    const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(600 * 1024)); }, cancel() { cancelled = true; } });
    const { value, context } = mutation("POST", ["action-plans", "demo", "cancel"], body, headers);
    const response = await api.POST(value, context);
    assert.equal(response.status, 413); assert.equal(calls.length, 0); assert.equal(cancelled, true);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
});
test("scope profile and draft creation accept at most 8 MiB of actual bytes", async () => {
  for (const endpoint of ["scan-scope-profiles", "selection-drafts", "resources/search"]) {
    const { api, calls } = setup("local");
    const segments = ["connections", "source", "synthetic", ...endpoint.split("/")];
    const accepted = mutation("POST", segments, "x".repeat(8 * 1024 * 1024));
    assert.equal((await api.POST(accepted.value, accepted.context)).status, 200);
    const rejected = mutation("POST", segments, "한".repeat(Math.floor(8 * 1024 * 1024 / 3) + 1));
    assert.equal((await api.POST(rejected.value, rejected.context)).status, 413);
    assert.equal(calls.length, 1);
  }
});
test("declared oversized bodies are rejected before stream reads or upstream forwarding", async () => {
  const { api, calls } = setup("local");
  let cancelled = false;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  const { value, context } = mutation("PATCH", ["scan-scope-profiles", "synthetic"], body, { "content-length": String(8 * 1024 * 1024 + 1) });
  assert.equal((await api.PATCH(value, context)).status, 413);
  assert.equal(cancelled, true); assert.equal(calls.length, 0);
});
test("scope preview and unrelated lookalike paths retain the ordinary mutation limit", async () => {
  for (const segments of [["scan-scope-profiles", "synthetic", "preview"], ["unrelated", "source", "synthetic", "selection-drafts"], ["connections", "source", "synthetic", "resources", "notion-search"], ["connections", "other", "synthetic", "resources", "search"], ["connections", "source", "synthetic", "resources", "search", "extra"]]) {
    const { api, calls } = setup("local");
    const { value, context } = mutation("POST", segments, "x".repeat(1024 * 1024 + 1));
    assert.equal((await api.POST(value, context)).status, 413); assert.equal(calls.length, 0);
  }
});
test("PATCH applies same-origin and OIDC session checks before reading its body", async () => {
  const { api, calls } = setup("oidc");
  for (const headers of [{ origin: "https://unrelated.example", authorization: "Bearer synthetic" }, { origin: "http://localhost:3301" }]) {
    const { value, context } = mutation("PATCH", ["scan-scope-profiles", "synthetic"], "{}", headers);
    assert.equal((await api.PATCH(value, context)).status, headers.authorization ? 403 : 401);
    assert.equal(value.bodyUsed, false);
  }
  assert.equal(calls.length, 0);
});

function hostRequest(method, host, headers = {}) {
  const value = new Request("http://localhost/api/backend/findings", { method, headers: { host, ...headers }, ...(method === "GET" ? {} : { body: "{}" }) });
  value.nextUrl = new URL(`http://localhost/api/backend/findings`);
  return value;
}
const findings = { params: Promise.resolve({ path: ["findings"] }) };

test("local mode refuses DNS-rebound hosts before attaching the admin token", async () => {
  const { api, calls } = setup("local");
  // A page on attacker.example rebound to 127.0.0.1 is same-origin with itself and may add X-Forwarded-Host.
  for (const [method, headers] of [["GET", {}], ["POST", { origin: "http://attacker.example:3100" }], ["POST", { origin: "http://attacker.example:3100", "x-forwarded-host": "localhost:3100" }]]) {
    const response = await api[method](hostRequest(method, "attacker.example:3100", headers), findings);
    assert.equal(response.status, 403, `${method} ${JSON.stringify(headers)}`);
    assert.doesNotMatch(await response.text(), /synthetic-server-only/);
  }
  for (const host of ["localhost.attacker.example:3100", "127.0.0.1.nip.io:3100", "localhost@attacker.example", "[::2]:3100", "localhost:3100/evil"]) {
    assert.equal((await api.GET(hostRequest("GET", host), findings)).status, 403, host);
  }
  assert.equal(calls.length, 0, "no rebound request reaches the API");
});

test("local mode accepts loopback hosts and explicitly configured hostnames only", async () => {
  const { api, calls } = setup("local");
  for (const host of ["localhost:3100", "LOCALHOST:3100", "127.0.0.1:3100", "[::1]:3100", "localhost"]) {
    assert.equal((await api.GET(hostRequest("GET", host), findings)).status, 200, host);
  }
  assert.equal(calls.length, 5);
  assert.equal(calls[0].options.headers.get("authorization"), "Bearer synthetic-server-only");
  const configured = setup("local", { CREMORE_ALLOWED_HOSTS: " cremore.internal , other.example " });
  assert.equal((await configured.api.GET(hostRequest("GET", "cremore.internal:3100"), findings)).status, 200);
  assert.equal((await configured.api.GET(hostRequest("GET", "cremore.internal.attacker.example:3100"), findings)).status, 403);
});

test("OIDC mode does not depend on the Host allowlist because the browser session carries identity", async () => {
  const { api, calls } = setup("oidc");
  const response = await api.GET(hostRequest("GET", "cremore.example.com", { authorization: "Bearer synthetic-oidc" }), findings);
  assert.equal(response.status, 200); assert.equal(calls[0].options.headers.get("authorization"), "Bearer synthetic-oidc");
});

test("OIDC mode never falls back to the local admin token, even though one is configured", async () => {
  // setup() always sets CREMORE_API_TOKEN=synthetic-server-only; a public deployment
  // runs in oidc mode so an external request must never reach the admin-token path.
  const { api, calls } = setup("oidc");
  // No browser session -> rejected, and nothing is forwarded (no admin fallback).
  assert.equal((await api.GET(hostRequest("GET", "cremore.example.com"), findings)).status, 401);
  assert.equal(calls.length, 0);
  // With a session -> the user's own token is forwarded, never the server credential.
  assert.equal((await api.GET(hostRequest("GET", "cremore.example.com", { authorization: "Bearer synthetic-oidc" }), findings)).status, 200);
  assert.equal(calls[0].options.headers.get("authorization"), "Bearer synthetic-oidc");
  assert.notEqual(calls[0].options.headers.get("authorization"), "Bearer synthetic-server-only");
});

test("unknown v2 namespaces cannot change the upstream API version", async () => {
  const { api, calls } = setup("local");
  const read = (segments) => {
    const value = new Request(`http://localhost:3301/api/backend/${segments.join("/")}`, { method: "GET", headers: { host: "localhost:3301" } });
    value.nextUrl = new URL(value.url);
    return [value, { params: Promise.resolve({ path: segments }) }];
  };
  assert.equal((await api.GET(...read(["coverage"]))).status, 200);
  assert.match(calls.at(-1).url.toString(), /\/api\/v1\/coverage$/);
  assert.equal((await api.GET(...read(["v2", "coverage", "inventory"]))).status, 200);
  assert.match(calls.at(-1).url.toString(), /\/api\/v2\/coverage\/inventory$/);
  const before = calls.length;
  for (const segments of [["v2", "findings"], ["v2"], ["v2", "coverage", ".."], ["v2", "", "coverage"]]) {
    assert.equal((await api.GET(...read(segments))).status, 404);
  }
  assert.equal(calls.length, before);
});

test("Google onboarding uses explicit v2 endpoints with existing session and origin checks", async () => {
  for (const mode of ["local", "oidc"]) {
    const { api, calls } = setup(mode);
    for (const endpoint of ["start", "finish", "projects", "complete", "cancel"]) {
      const headers = mode === "oidc" ? { authorization: "Bearer synthetic-oidc" } : {};
      const accepted = mutation("POST", ["v2", "gcp", "oauth", endpoint], "{}", headers);
      assert.equal((await api.POST(accepted.value, accepted.context)).status, 200);
      assert.equal(calls.at(-1).url.toString(), `http://127.0.0.1:3302/api/v2/gcp/oauth/${endpoint}`);
      const rejected = mutation("POST", ["v2", "gcp", "oauth", endpoint], "{}", { ...headers, origin: "https://other.example" });
      assert.equal((await api.POST(rejected.value, rejected.context)).status, 403);
    }
    // The Google OAuth client an admin saves in the dashboard (PUT client), under the same origin check.
    const headers = mode === "oidc" ? { authorization: "Bearer synthetic-oidc" } : {};
    const saved = mutation("PUT", ["v2", "gcp", "oauth", "client"], "{}", headers);
    assert.equal((await api.PUT(saved.value, saved.context)).status, 200);
    assert.equal(calls.at(-1).url.toString(), "http://127.0.0.1:3302/api/v2/gcp/oauth/client");
    const foreign = mutation("PUT", ["v2", "gcp", "oauth", "client"], "{}", { ...headers, origin: "https://other.example" });
    assert.equal((await api.PUT(foreign.value, foreign.context)).status, 403);
    for (const segments of [["v2", "gcp", "oauth", "unknown"], ["v2", "gcp", "other", "start"], ["v2", "gcp", "oauth", "start", "extra"]]) {
      const input = mutation("POST", segments, "{}", headers);
      assert.equal((await api.POST(input.value, input.context)).status, 404);
    }
    assert.equal(calls.length, 6);
  }
});

test("a v2 coverage read keeps the same credential, no-store and referrer policy", async () => {
  const { api, calls } = setup("local");
  const segments = ["v2", "coverage", "connections"];
  const value = new Request(`http://localhost:3301/api/backend/${segments.join("/")}`, { method: "GET", headers: { host: "localhost:3301" } });
  value.nextUrl = new URL(value.url);
  const response = await api.GET(value, { params: Promise.resolve({ path: segments }) });
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(calls.at(-1).options.redirect, "error");
  assert.match(calls.at(-1).options.headers.get("Authorization"), /synthetic-server-only/);
  assert.doesNotMatch(await response.text(), /synthetic-server-only/);
});

test("array pagination headers reach the browser without forwarding unrelated headers", async () => {
  const cursor = "11111111-1111-4111-8111-111111111111";
  const { api } = setup("local", {}, () => Response.json([], { headers: {
    "X-Next-Cursor": cursor, "X-Page-Limit": "100", "X-Private-Internal": "not-for-client",
  } }));
  const value = new Request("http://localhost:3301/api/backend/management-actions?limit=100", { headers: { host: "localhost:3301" } });
  value.nextUrl = new URL(value.url);
  const response = await api.GET(value, { params: Promise.resolve({ path: ["management-actions"] }) });
  assert.equal(response.headers.get("X-Next-Cursor"), cursor);
  assert.equal(response.headers.get("X-Page-Limit"), "100");
  assert.equal(response.headers.get("X-Private-Internal"), null);
  assert.deepEqual(await response.json(), []);
});
