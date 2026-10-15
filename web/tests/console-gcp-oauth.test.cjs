// The console's Google sign-in start (console/gcp-oauth.ts): the browser leaves only for Google's own authorization
// page, and keeps nothing when the API names another. No network: the API answer is scripted.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

function start(authorization_url) {
  const stored = new Map(), assigned = [], sent = [];
  const globals = {
    sessionStorage: { getItem: key => stored.get(key) ?? null, setItem: (key, value) => stored.set(key, value), removeItem: key => stored.delete(key) },
    window: { location: { assign: url => assigned.push(url) } },
  };
  const api = async (path, init) => { sent.push({ path, body: JSON.parse(init.body) }); return { session_id: "s-1", state: "synthetic-state", expires_at: "2099-01-01T00:00:00Z", authorization_url }; };
  const oauth = load("@/console/gcp-oauth.ts", { globals, overrides: { "@/lib/dashboard-api": { api } } });
  return { oauth, stored, assigned, sent };
}

test("a sign-in leaves only for Google's authorization page", async () => {
  const good = start("https://accounts.google.com/o/oauth2/v2/auth?client_id=synthetic");
  await good.oauth.startSignIn("p-gcp", "en");
  assert.deepEqual(good.assigned, ["https://accounts.google.com/o/oauth2/v2/auth?client_id=synthetic"]);
  const session = JSON.parse(good.stored.get("cremore.gcp.oauth.pending"));
  assert.equal(session.locale, "en");
  assert.equal(session.browser_key, good.sent[0].body.browser_key, "the browser keeps the key it sent");
  assert.deepEqual({ ...good.sent[0].body, browser_key: "" }, { browser_key: "", connection_id: "p-gcp", connection_kind: "provider" });
  for (const url of ["https://accounts.google.com.evil.test/o/oauth2/v2/auth", "http://accounts.google.com/o/oauth2/v2/auth",
    "https://accounts.google.com/o/oauth2/auth", "https://evil.test/o/oauth2/v2/auth"]) {
    const other = start(url);
    await assert.rejects(other.oauth.startSignIn("p-gcp", "ko"), /GCP_OAUTH_RESPONSE_INVALID/, url);
    assert.deepEqual(other.assigned, [], url);
    assert.equal(other.stored.size, 0, url);
  }
});
