const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const ts = require("typescript");
const { source } = require("./load-module.cjs");
const code = ts.transpileModule(source("@/app/api/v1/hooks/notion/[binding]/route.ts"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const binding = "11111111-2222-3333-4444-555555555555";
function setup(status = 200) {
  const loaded = { exports: {} }, calls = [];
  vm.runInNewContext(code, { module: loaded, exports: loaded.exports, URL, Response, Uint8Array, AbortSignal,
    process: { env: { CREMORE_API_URL: "http://api:8080", CREMORE_API_TOKEN: "NEVER_FORWARD" } },
    fetch: async (url, init) => { calls.push({ url, init }); return new Response("ignored", { status }); },
  });
  return { handler: loaded.exports.POST, calls };
}
function request(body, headers = {}) {
  return new Request(`https://dashboard.example/api/v1/hooks/notion/${binding}`, { method: "POST", body,
    headers: { authorization: "Bearer USER_SESSION", cookie: "private=session", ...headers },
    ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
  });
}
test("machine ingress preserves signed bytes without forwarding any credentials", async () => {
  const { handler, calls } = setup();
  const raw = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d, 0x0a]);
  const signature = "sha256=" + "a".repeat(64);
  const response = await handler(request(raw, { "x-notion-signature": signature }), { params: Promise.resolve({ binding }) });
  assert.equal(response.status, 200);
  assert.deepEqual([...calls[0].init.body], [...raw]);
  assert.equal(calls[0].init.headers["X-Notion-Signature"], signature);
  assert.deepEqual(Object.keys(calls[0].init.headers).sort(), ["Content-Type", "X-Notion-Signature"]);
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(await response.text(), "");
});
test("public ingress bounds actual bytes and only forwards UUID routes", async () => {
  const { handler, calls } = setup();
  const context = { params: Promise.resolve({ binding }) };
  assert.equal((await handler(request(new Uint8Array(65537)), context)).status, 413);
  assert.equal((await handler(request("{}"), { params: Promise.resolve({ binding: "../../settings" }) })).status, 404);
  assert.equal((await handler(request("{}", { "x-notion-signature": "bad" }), context)).status, 403);
  assert.equal(calls.length, 0);
});
test("upstream failure is never acknowledged as successful delivery", async () => {
  const { handler } = setup(503);
  assert.equal((await handler(request("{}"), { params: Promise.resolve({ binding }) })).status, 503);
});
