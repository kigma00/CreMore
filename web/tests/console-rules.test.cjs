// The console's detection rules: reading a pattern, trying samples in the browser, the rule list's
// filters and order, and the request a rule form sends. Synthetic rules and samples only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const rx = load("@/console/views/rules/regex.ts");
const rules = load("@/console/views/rules/page.tsx");

const L = (ko, en) => ko;
const E = (ko, en) => en;
const plain = value => JSON.parse(JSON.stringify(value));

test("a pattern reads as the value it reports and the name before it", () => {
  const deploy = rx.parse("(?:^|[^A-Za-z0-9_])(?P<secret>dpl_[A-Za-z0-9]{40})");
  assert.deepEqual(plain(rx.parts(deploy, L)), { value: "'dpl_' → 영문·숫자 40자", label: "" });
  assert.equal(rx.isBound(deploy[0][0]), true);
  assert.match(rx.groupTip(deploy[0][0], L), /^경계: 바로 앞뒤에 영문·숫자·'_' 글자가/);
  const pay = rx.parse("(?P<secret>demo_pay_(?:live|test)_[0-9a-f]{32})");
  assert.equal(rx.parts(pay, E).value, "'demo_pay_' → ('live' or 'test') → '_' → hex (0–9, a–f) ×32");
  const labelled = rx.parse("(?i:api[_-]?key)[\"'\\s:=]{1,8}(?P<secret>[a-f0-9]{32})");
  assert.deepEqual(plain(rx.parts(labelled, L)), { value: "16진수(0~9·a~f) 32자", label: "'api' → '_'·'-' (생략 가능) → 'key' → '\"'·'''·공백·':'·'=' 1~8자" });
  assert.equal(rx.nodeTip(rx.parse("(?i)x")[0][0], L), "이 뒤로는 대소문자를 가리지 않습니다");
  assert.equal(rx.quantTip({ raw: "{2,}", min: 2, max: Infinity }, L), "바로 앞이 2번 이상");
  for (const pattern of ["(?:^|[^A-Za-z0-9_])(?P<secret>dpl_[A-Za-z0-9]{40})", "a{2,3}?(b|c)*[^\\s]+\\z", "(?P<id>AKIA[0-9A-Z]{16})"]) {
    const flat = rx.parse(pattern).map(list => list.map(node => node.raw + (node.q ? node.q.raw : "")).join("")).join("|");
    assert.equal(flat, pattern, "every piece keeps its text");
  }
});

test("a sample is tried in the browser with RE2 syntax translated", () => {
  assert.equal(String(rx.toJsRe("(?i)abc\\z")), "/abc$/gi");
  assert.equal(String(rx.toJsRe("\\A[[:digit:]]+")), "/^[0-9]+/g");
  assert.equal(String(rx.toJsRe("\\pL{3}")), "/\\p{L}{3}/gu");
  assert.equal(String(rx.toJsRe("(?P<secret>x+)")), "/(?<secret>x+)/g");
  assert.equal(rx.toJsRe("(unclosed"), null);
  const found = rx.hits("key=(?P<secret>dpl_[a-z]{4})", "key=dpl_abcd\n# example key=dpl_wxyz", ["Example"]);
  assert.deepEqual(plain(found), [{ start: 4, end: 12, skip: false }, { start: 27, end: 35, skip: true }]);
  assert.equal(rx.hits("x", "", []), null);
  for (const pattern of ["(?:^|[^A-Za-z0-9_])(?P<secret>dpl_[A-Za-z0-9]{40})", "(?i:token)[=:](?P<secret>[A-F0-9]{8,12})", "ghp_[A-Za-z0-9]{36}(?:$|[^A-Za-z0-9_-])"]) {
    const re = rx.toJsRe(pattern), sample = rx.synth(pattern);
    assert.ok(re.test(sample), `${pattern} matches its synthetic ${JSON.stringify(sample)}`);
  }
  assert.equal(rx.synth("(?P<secret>demo_pay_(?:live|test)_[0-9a-f]{32})"), "demo_pay_live_" + "a".repeat(32));
});

test("the form's checks follow the server's RE2 verdict and what the browser can tell", () => {
  const form = (expr, name = "In-house key", kw = "") => ({ name, expr, kw });
  const states = checks => plain(checks.map(check => check.ok));
  assert.deepEqual(states(rx.ruleChecks(form("(?P<secret>dpl_[a-z]{40})"), false, { state: "pending" }, L)), [true, true, true, null, null, true]);
  assert.deepEqual(states(rx.ruleChecks(form("(?P<secret>dpl_[a-z]{40})"), false, { state: "done", error: null }, L)), [true, true, true, true, true, true]);
  assert.deepEqual(states(rx.ruleChecks(form("[a-z"), false, { state: "done", error: "pattern does not compile: error" }, L)), [true, true, true, false, null, true]);
  assert.deepEqual(states(rx.ruleChecks(form(".*"), false, { state: "done", error: "pattern matches trivial input; it would flag almost anything" }, L)), [true, true, true, true, false, true]);
  const named = rx.ruleChecks(form("(?<secret>abc)"), true, { state: "idle" }, L);
  assert.equal(named[0].ok, false);
  assert.equal(named[0].why, "같은 이름의 룰이 이미 있습니다.");
  assert.equal(named[2].ok, false);
  assert.match(named[2].why, /\(\?P<이름>/);
  assert.equal(rx.ruleChecks(form("x".repeat(1001)), false, { state: "idle" }, L)[1].ok, false);
  assert.equal(rx.ruleChecks(form("abc", "n", Array.from({ length: 33 }, (_, i) => `k${i}`).join(",")), false, { state: "idle" }, L)[5].ok, false);
});

const detector = (id, changes = {}) => ({ id, name: `Detector ${id}`, provider: "github", credential_type: "GITHUB_TOKEN", category: "token",
  description: "Synthetic.", confidence: "high", keywords: ["ghp_"], strategy: "prefix", patterns: ["ghp_[A-Za-z0-9]{36}"], enabled: true, ...changes });
const orgRule = (id, changes = {}) => ({ id, name: `Rule ${id}`, description: "", enabled: true, keywords: ["dpl_"], pattern: "(?P<secret>dpl_[A-Za-z0-9]{40})",
  severity: "HIGH", revision: 2, scope_sources: [], include_globs: ["src/**"], exclude_globs: [], exclude_words: [], provider_candidates: [], category: "token",
  updated_by: "admin", updated_at: "2026-09-27T01:00:00Z", ...changes });

test("organization rules come first; filters, search and sort work on one list", () => {
  const list = rules.rulesOf([detector("b-slack", { name: "Slack bot", provider: "slack", category: "token" }), detector("a-aws", { name: "AWS key", provider: "aws", category: "apikey", enabled: false }),
    detector("g-generic", { name: "Password", provider: "", category: "account", keywords: ["passwd"] })],
  [orgRule("11111111-1111-1111-1111-111111111111", { name: "Deploy bot", category: null, provider_candidates: ["slack"] })]);
  assert.deepEqual(plain(list.map(r => [r.id, r.builtin, r.cat, r.type, r.on])), [
    ["custom-11111111-1111-1111-1111-111111111111", false, "slack", "other", true],
    ["b-slack", true, "slack", "token", true], ["a-aws", true, "aws", "apikey", false], ["g-generic", true, "generic", "account", true]]);
  const names = rows => plain(rows.map(r => r.name));
  assert.deepEqual(names(rules.sortRules(list, "name", "asc", L)), ["Deploy bot", "AWS key", "Password", "Slack bot"]);
  assert.deepEqual(names(rules.sortRules(list, "name", "desc", L)), ["Deploy bot", "Slack bot", "Password", "AWS key"]);
  assert.deepEqual(names(rules.sortRules(list, "type", "asc", L)), ["Deploy bot", "Slack bot", "AWS key", "Password"]);
  assert.deepEqual(names(list.filter(r => rules.matches(r, { state: ["off"] }, "", L))), ["AWS key"]);
  assert.deepEqual(names(list.filter(r => rules.matches(r, { creator: ["builtin"], cat: ["slack"] }, "", L))), ["Slack bot"]);
  assert.deepEqual(names(list.filter(r => rules.matches(r, { cat: ["slack"] }, "", L, "cat"))), names(list));
  assert.deepEqual(names(list.filter(r => rules.matches(r, {}, "PASSWD", L))), ["Password"]);
  assert.deepEqual(names(list.filter(r => rules.matches(r, {}, "공통 형식", L))), ["Password"]);
  assert.equal(rules.catLabel("custom", L), "사내 자체 형식");
  assert.equal(rules.filterValue("creator", list[0]), "org");
});

test("a rule form sends the fields the server stores; a copy says where it came from", () => {
  const [org, builtin] = rules.rulesOf([detector("github-pat-v1", { name: "GitHub PAT", provider: "github" })],
    [orgRule("22222222-2222-2222-2222-222222222222", { name: "Pay key", severity: "CRITICAL", scope_sources: ["github"], exclude_words: ["example"], exclude_globs: ["**/test/**"] })]);
  const copied = rules.formOf(builtin, true, L);
  assert.deepEqual(plain(copied), { name: "GitHub PAT (사내용)", desc: "Synthetic.", type: "token", cat: "github", sev: "HIGH", expr: "ghp_[A-Za-z0-9]{36}",
    kw: "ghp_", scope: [], exWords: "", exPaths: "" });
  assert.deepEqual(plain(rules.bodyOf({ ...copied, cat: "custom", kw: " a, ,b ", exWords: "x", exPaths: "*.md" }, builtin)), {
    name: "GitHub PAT (사내용)", description: "Synthetic.", category: "token", provider_candidates: [], severity: "HIGH", pattern: "ghp_[A-Za-z0-9]{36}",
    keywords: ["a", "b"], scope_sources: [], exclude_words: ["x"], exclude_globs: ["*.md"] });
  const edited = rules.formOf(org, false, L);
  assert.equal(edited.sev, "CRITICAL");
  assert.deepEqual(plain(rules.bodyOf(edited, org)), { name: "Pay key", description: "", category: "token", provider_candidates: [], severity: "CRITICAL",
    pattern: "(?P<secret>dpl_[A-Za-z0-9]{40})", keywords: ["dpl_"], scope_sources: ["github"], exclude_words: ["example"], exclude_globs: ["**/test/**"], include_globs: ["src/**"] });
});
