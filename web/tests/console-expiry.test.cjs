// A token's expiry and a vendor's services in the console: the day an admin enters is the end of that day in their
// time zone (as the Operations page enters it), it is saved on each owned record that takes it, the bell warns once
// per connection, and Atlassian's services name each other. Synthetic connections and health only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const plain = value => JSON.parse(JSON.stringify(value));
const L = (ko, en) => ko;

test("an entered expiry is the end of that day where the admin is, and reads back as that day", () => {
  assert.equal(model.expiryAt("2026-12-31"), new Date("2026-12-31T23:59:59").toISOString());
  assert.equal(model.expiryDay(model.expiryAt("2026-12-31")), "2026-12-31");
  assert.equal(model.expiryAt(""), null);
  assert.equal(model.expiryDay(null), "");
});

test("only a method holding a token takes a date", () => {
  const secret = [{ name: "token", label: "t", label_ko: "t", kind: "secret", secret: true }];
  assert.equal(model.takesExpiry({ id: "token", renewal: "EXPIRES", fields: secret }), true);
  // AWS Identity Center is a person's sign-in: it expires, but there is no token to date.
  assert.equal(model.takesExpiry({ id: "sso", renewal: "EXPIRES", fields: [] }), false);
  assert.equal(model.takesExpiry({ id: "app", renewal: "AUTOMATIC", fields: secret }), false);
});

const conn = (id, name, children) => ({ id, name, children });
const item = (key, extra = {}) => ({ key, name: key, auth_state: "UNKNOWN", auth_renewal: "MANUAL", expires_at: null, expires_source: null, ...extra });

test("the date goes to each owned record that takes it, and a refused one is named", async () => {
  const c = conn("c1", "Bitbucket · acme", [{ kind: "content", id: "a" }, { kind: "metadata", id: "b" }, { kind: "metadata", id: "d" }, { kind: "metadata", id: "p" }]);
  const health = [item("content:a"), item("coverage:b"), item("coverage:d", { auth_state: "DISABLED" }),
    item("coverage:p", { expires_source: "PROVIDER" }), item("coverage:other")];
  assert.deepEqual(plain(model.expiryKeys(c, health, "2026-12-31")), ["content:a", "coverage:b"]);
  // Saving again changes only the records not on that day yet; clearing touches only entered dates.
  const saved = [item("content:a", { expires_source: "OPERATOR", expires_at: model.expiryAt("2026-12-31") }), item("coverage:b"),
    item("coverage:d", { auth_state: "DISABLED" }), item("coverage:p", { expires_source: "PROVIDER" })];
  assert.deepEqual(plain(model.expiryKeys(c, saved, "2026-12-31")), ["coverage:b"]);
  assert.deepEqual(plain(model.expiryKeys(c, saved, "2027-01-15")), ["content:a", "coverage:b"]);
  assert.deepEqual(plain(model.expiryKeys(c, saved, "")), ["content:a"]);
  const sent = [];
  const put = (key, body) => { sent.push([key, body.expires_at]); return key === "coverage:b" ? Promise.reject(new Error("404")) : Promise.resolve({}); };
  assert.deepEqual(plain(await model.saveExpiry(put, ["content:a", "coverage:b"], "2026-12-31")), ["coverage:b"]);
  assert.deepEqual(sent, [["content:a", model.expiryAt("2026-12-31")], ["coverage:b", model.expiryAt("2026-12-31")]]);
  sent.length = 0;
  assert.deepEqual(plain(await model.saveExpiry(put, ["content:a"], "")), []);
  assert.deepEqual(sent, [["content:a", null]]);
});

test("the bell warns once per connection, and apart for connections that share a date", () => {
  const soon = "2026-10-06T14:59:59.000Z";
  const connections = [conn("c1", "Bitbucket · acme", [{ kind: "content", id: "a" }, { kind: "metadata", id: "b" }]),
    conn("c2", "Confluence · 42", [{ kind: "content", id: "z" }])];
  const health = [item("content:a", { auth_state: "EXPIRING", expires_at: soon }), item("coverage:b", { auth_state: "EXPIRING", expires_at: soon }),
    item("content:z", { auth_state: "EXPIRING", expires_at: soon }), item("coverage:loose", { auth_state: "EXPIRING", expires_at: soon }),
    item("coverage:ok", { auth_state: "READY", expires_at: soon })];
  assert.deepEqual(plain(model.expiringConnections(health, connections).map(entry => [entry.key, entry.name])), [
    ["connection:c1", "Bitbucket · acme"], ["connection:c2", "Confluence · 42"], ["coverage:loose", "coverage:loose"]]);
});

test("an expiring sign-in is said before the wait for a first run", () => {
  const c = { id: "c1", provider: "bitbucket", edition: "cloud", name: "Bitbucket · acme", status: "ACTIVE", revision: 2, purposes: ["exposure"],
    plans: { exposure: {} }, auth_method: "access_token", credential: { roles: ["credential"], reference: false },
    children: [{ kind: "content", id: "a" }], target: { workspace: "acme" },
    checks: { results: {}, checked_at: "2026-09-29T02:00:00Z", requested_at: null, job_id: null, stale: false, error: null } };
  const now = Date.parse("2026-09-29T00:00:00Z");
  const health = [{ ...item("content:a", { auth_state: "EXPIRING", expires_at: "2026-10-06T00:00:00Z", expiry_stage: "D14" }),
    last_success_at: null, last_status: "NOT_COLLECTED" }];
  const row = model.rowState(c, health, L, now);
  assert.equal(row.tone, "warn");
  assert.equal(row.note, "연동 인증이 7일 뒤 만료됩니다");
});

test("Atlassian's services lead to one another; others stand alone", () => {
  assert.deepEqual(plain(model.familyOf("bitbucket")), { name: "Atlassian", others: ["confluence", "atlassian"] });
  assert.deepEqual(plain(model.familyOf("atlassian").others), ["confluence", "bitbucket"]);
  assert.equal(model.familyOf("github"), null);
  assert.equal(model.healthKey({ kind: "aws_account", id: "a1" }), "aws_account:a1");
});
