// The console: routes, derived facts, risk rules, guides and the credential panel's markup,
// rendered from synthetic credential rows. No network, service or browser.
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load, source } = require("./load-module.cjs");

const nav = load("@/console/nav.ts");
const text = load("@/console/text.ts");
const records = load("@/console/records.ts");
const checks = load("@/console/checks.ts");
const risk = load("@/console/views/credentials/risk.ts");
const labels = load("@/console/labels.ts");
const links = load("@/console/source-links.ts");
const ui = load("@/console/ui.tsx");
const locale = load("@/components/locale.tsx");
const data = load("@/console/data.ts");
const api = load("@/lib/dashboard-api.ts");

const L = (ko, en) => ko;
const NOW = Date.parse("2026-09-27T01:00:00Z");
const day = 86_400_000;

function row(changes = {}) {
  return {
    id: "credential:1", credential_id: "1", finding_id: "f-1", entity_id: null, provider: "github", credential_type: "GITHUB_TOKEN",
    category: "token", kind: "token", name: null, hint: "ghp_••••2zC4", exposed: true, status: "pending", workflow_status: "OPEN", risk: "high",
    acknowledged_at: null, resolved_at: null,
    verification: { state: "unknown", at: null, basis: null, reason: "NOT_REQUESTED" }, owner: null, issuer: null,
    exposures: [{ source_type: "github", resource_name: "acme/app", location: "config/prod.yml", line: 4, snippet: "token: ••••", visibility: "public", current: true,
      first_seen_at: "2026-09-20T00:00:00Z", last_seen_at: "2026-09-26T00:00:00Z" }],
    exposure_count: 1, location_count: 1, first_seen_at: "2026-09-20T00:00:00Z", last_seen_at: "2026-09-26T00:00:00Z",
    created_at: null, expires_at: null, expiry: "unknown", last_used: null, scopes: null,
    vault: { state: "unknown", where: [], basis: "UNKNOWN", reasons: ["NO_VAULT_CONNECTED"], absence_basis: null },
    tags: [], stage: null, steps: {}, contact: null, annotations_revision: 0, review: null, issued: null, ...changes,
  };
}

function html(element) {
  return renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "ko" }, element));
}

test("a random id is a version 4 UUID made without a secure context", () => {
  // crypto.randomUUID is missing on an installation reached over plain http on another host.
  const insecure = load("@/console/data.ts", { globals: { crypto: { getRandomValues: array => require("node:crypto").getRandomValues(array) } } });
  const ids = new Set(Array.from({ length: 50 }, () => insecure.randomId()));
  assert.equal(ids.size, 50);
  for (const id of ids) assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  // Nowhere in the console is an id made by crypto.randomUUID.
  const root = require("node:path").join(__dirname, "../console");
  const files = require("node:fs").readdirSync(root, { recursive: true }).filter(name => /\.tsx?$/.test(name));
  assert.ok(files.length > 50, "the console's files");
  for (const name of files) assert.doesNotMatch(source(`@/console/${name.replaceAll("\\", "/")}`), /\brandomUUID\b\s*(?:\(|[,}])/, name);
});

test("an address kept from /console or the old /demo page opens the console at /", async () => {
  // Next passes the query through a redirect (node_modules/next/dist/docs/.../next-config-js/redirects.md).
  const config = load("@/next.config.ts", { globals: { __dirname: require("node:path").join(__dirname, "..") } }).default;
  assert.deepEqual(JSON.parse(JSON.stringify(await config.redirects())), [
    { source: "/console", destination: "/", permanent: false },
    { source: "/demo", destination: "/", permanent: false },
  ]);
});

test("a URL names one screen; anything else opens the overview", () => {
  assert.equal(nav.readRoute("?view=exposed&id=credential%3A1").view, "exposed");
  assert.equal(nav.readRoute("?view=exposed&id=credential%3A1").params.get("id"), "credential:1");
  assert.equal(nav.readRoute("?view=nope").view, "dashboard");
  assert.equal(nav.readRoute("").view, "dashboard");
  assert.equal(nav.routeHref("inventory", { cat: "token", q: null }), "?view=inventory&cat=token");
  for (const item of nav.VIEWS) assert.ok(["Viewer", "Analyst", "Remediator", "Admin"].includes(item.role), item.id);
  // Screens that change installation settings are offered to admins only.
  for (const id of ["sources", "rules", "audit", "operations", "settings"]) assert.equal(nav.navItem(id).role, "Admin", id);
  // No provider has a screen of its own: AWS accounts belong to the AWS integration like any provider's targets.
  assert.equal(nav.isView("accounts"), false);
});

test("dates read in the display timezone, with the year only when it is not this year", () => {
  assert.equal(text.fmtDay("2026-09-26T16:30:00Z", "ko", "Asia/Seoul", NOW), "9월 27일");
  assert.equal(text.fmtDay("2026-09-26T16:30:00Z", "en", "UTC", NOW), "Sep 26");
  assert.equal(text.fmtDay("2025-01-02T00:00:00Z", "ko", "UTC", NOW), "2025년 1월 2일");
  assert.equal(text.fmtDay("2026-10-01", "ko", "Asia/Seoul", NOW), "10월 1일");
  assert.equal(text.fmtDT("2026-09-26T16:30:00Z", "ko", "Asia/Seoul", NOW), "9월 27일 01:30");
  assert.equal(text.fmtDay(null, "ko"), "—");
  assert.equal(text.fmtDay("0001-01-01T00:00:00Z", "ko"), "—");
  assert.equal(text.rel(new Date(NOW - 3 * 3_600_000).toISOString(), "ko", NOW), "3시간 전");
  assert.equal(text.rel(new Date(NOW + 2 * day).toISOString(), "en", NOW), "in 2d");
  assert.equal(text.daysLeft(new Date(NOW + 10 * day).toISOString(), NOW), 10);
});

test("what a row means: open, countable, expiring, stale, public, overdue", () => {
  assert.equal(records.isOpen(row()), true);
  assert.equal(records.isOpen(row({ status: "done" })), false);
  assert.equal(records.countable(row({ status: "fp" })), false);
  assert.equal(records.countable(row({ status: "done" })), true);
  assert.equal(records.expSoon(row({ expiry: "date", expires_at: new Date(NOW + 20 * day).toISOString() }), NOW), true);
  assert.equal(records.expSoon(row({ expiry: "date", expires_at: new Date(NOW + 40 * day).toISOString() }), NOW), false);
  assert.equal(records.noExpiry(row({ expiry: "none" })), true);
  assert.equal(records.noExpiry(row({ expiry: "none", verification: { state: "revoked", at: null, basis: null, reason: null } })), false);
  assert.equal(records.stale(row({ last_used: { at: new Date(NOW - 100 * day).toISOString(), basis: "ISSUER_REPORTED" } }), NOW), true);
  assert.equal(records.worstVis(row({ exposures: [{ ...row().exposures[0], visibility: "private" }, { ...row().exposures[0], visibility: "org" }] })), "org");
  assert.equal(records.worstVis(row({ exposures: [{ ...row().exposures[0], current: false }] })), null);
  const contact = { channel: "mail", template: "revoke", recipients: 1, due_at: "2026-09-20", at: "2026-09-17T00:00:00Z", by: "a" };
  assert.equal(records.overdue(row({ contact }), NOW), true);
  assert.equal(records.overdue(row({ contact, status: "done" }), NOW), false);
});

test("overview counts and the open-exposure trend come from the rows", () => {
  const items = [row(), row({ id: "credential:2", status: "done", resolved_at: "2026-09-22T00:00:00Z" }), row({ id: "credential:3", status: "fp" }),
    row({ id: "issued:1", exposed: false, status: null, exposures: [], vault: { state: "stored", where: [], basis: "MATCHED", reasons: [], absence_basis: null } })];
  const s = checks.stats(items);
  assert.deepEqual({ total: s.total, exposed: s.exposed, open: s.open, done: s.done, fp: s.fp, vault: s.vault, pending: s.pending },
    { total: 4, exposed: 2, open: 1, done: 1, fp: 1, vault: 1, pending: 1 });
  // A week ago the resolved row was still open (it closed on the 22nd); the false positive row has no close time.
  assert.deepEqual([...checks.openTrend(items, NOW, 2)], [3, 1]);
  assert.equal(checks.CHECK_BY.public.test(row(), NOW), true);
  assert.equal(checks.CHECK_BY.noowner.test(row(), NOW), true);
  assert.equal(checks.CHECK_BY.noowner.test(row({ owner: { name: "kim", team: null, basis: "ASSIGNED" } }), NOW), false);
});

test("risk rules raise, lower or wait for evidence, and the axes follow them", () => {
  const active = row({ verification: { state: "active", at: "2026-09-26T00:00:00Z", basis: "ACTIVE_VERIFICATION", reason: null },
    scopes: [{ name: "repo", write: true }], vault: { state: "none", where: [], basis: "NO_VAULT_MATCH", reasons: [], absence_basis: "API_LISTING" }, expiry: "none" });
  const rules = risk.rulesFor(active, L, "ko", NOW);
  const labelsOf = axis => [...rules.filter(rule => rule.axis === axis).map(rule => rule.label)];
  assert.deepEqual(labelsOf("exposure"), ["공개 위치에 노출", "변경 이력에 남음"]);
  assert.ok(labelsOf("likelihood").includes("활성 상태 확인"));
  assert.ok(labelsOf("likelihood").includes("쓰기·관리 scope 관측"));
  assert.ok(labelsOf("likelihood").includes("Vault에 없음"));
  assert.equal(risk.axisLevel(rules, "likelihood", L).cls, "l-high");
  assert.equal(risk.axisLevel(rules, "exposure", L).cls, "l-high");
  assert.ok(labelsOf("unknown").includes("대응 담당자 미확인"));
  // Unknown activity is kept as "no evidence", never dropped.
  assert.ok(risk.rulesFor(row(), L, "ko", NOW).some(rule => rule.axis === "unknown" && rule.label === "활성 여부 미확인"));
  const reads = risk.rulesFor(row({ scopes: [{ name: "read", write: false }] }), L, "ko", NOW);
  const readScope = reads.find(rule => rule.label === "읽기 scope 관측");
  assert.equal(readScope.tone, "unknown");
  assert.match(readScope.desc, /실제 쓰기 권한이 없다는 보장은 아닙니다/);
  assert.ok(!risk.rulesFor(row({ scopes: [] }), L, "ko", NOW).some(rule => rule.label === "읽기 scope 관측"));
  const items = [...risk.remediationFor(active, L).map(item => item.id)];
  assert.deepEqual(items, ["revoke", "cleanup", "vault", "scope"]);
  assert.deepEqual([...risk.remediationFor(row({ verification: { state: "revoked", at: null, basis: null, reason: null }, exposed: true }), L).map(item => item.id)], ["cleanup"]);
});

test("guides place names as text, never as markup", () => {
  const filled = risk.fillSteps("<b>{name}</b> by {issuer}", "<img src=x onerror=alert(1)>", "a&b", "");
  assert.equal(filled, "<b>&lt;img src=x onerror=alert(1)&gt;</b> by a&amp;b");
  assert.equal(risk.plainSteps(["Open <b>{name}</b>", "Delete it"], "tok", "iss", ""), "1. Open tok\n2. Delete it");
  assert.equal(risk.plainSteps(["Use <code>{hint}</code> for <b>{issuer}</b>"], "tok", "team <ops>", "secret/example"),
    "1. Use secret/example for team <ops>");
});

test("verification and usage are described by where they came from", () => {
  assert.equal(risk.verifyBasis(row(), L), "발견 Credential 검증이 꺼져 있음");
  assert.equal(risk.verifyBasis(row({ exposed: false, verification: { state: "unknown", at: null, basis: null, reason: null } }), L), "노출되지 않아 검증 대상 아님");
  assert.equal(risk.verifyBasis(row({ verification: { state: "active", at: null, basis: "ACTIVE_VERIFICATION", reason: null } }), L), "GitHub 인증 확인");
  assert.equal(risk.verifyBasis(row({ verification: { state: "inactive", at: null, basis: "ISSUER_REPORTED", reason: null } }), L), "GitHub 발급 목록의 상태");
  const inventoryOwner = row({ verification: { state: "unknown", at: null, basis: "IAM_INVENTORY", reason: null } });
  assert.equal(risk.verifyBasis(inventoryOwner, L), "IAM 발급 목록");
  assert.equal(risk.verifyBasis(inventoryOwner, (_ko, en) => en), "IAM inventory");
  assert.equal(risk.usageGap(row(), L), "GitHub 사용 기록을 연결하지 않음");
});

test("codes read as words; unknown ones still read", () => {
  assert.equal(labels.typeLabel("AWS_ACCESS_KEY", L), "AWS 액세스 키");
  assert.equal(labels.typeLabel("CUSTOM_RULE_" + "A".repeat(64), L), "조직 룰 일치");
  assert.equal(labels.typeLabel("SOME_NEW_TOKEN", L, new Map([["SOME_NEW_TOKEN", "Some new token"]])), "Some new token");
  assert.equal(labels.typeLabel("SOME_NEW_TOKEN", L), "Some New Token");
  assert.equal(labels.actorLabel("00000000-0000-0000-0000-000000000001", L), "로컬 관리자");
  assert.equal(labels.actorLabel("github-schedule", L), "예약 작업");
  assert.equal(labels.actorLabel("kim@example.com", L), "kim@example.com");
});

test("only an approved original-source link opens", () => {
  const github = url => links.sourceOriginalURL({ source_provider: "github", coordinate_basis: "EXACT_ORIGINAL", context_status: "",
    original_link: { status: "AVAILABLE", url, requires_source_auth: true, historical_content: true } });
  assert.equal(github(`https://github.com/acme/app/blob/${"a".repeat(40)}/config/prod.yml#L4`), `https://github.com/acme/app/blob/${"a".repeat(40)}/config/prod.yml#L4`);
  assert.equal(github("javascript:alert(1)"), null);
  assert.equal(github(`http://github.com/acme/app/blob/${"a".repeat(40)}/x`), null);
  assert.equal(github(`https://evil.example/acme/app/blob/${"a".repeat(40)}/x`), null);
  assert.equal(github(`https://user:pw@github.com/acme/app/blob/${"a".repeat(40)}/x`), null);
});

test("a refusal reads as a sentence, a stale write says to reload", () => {
  assert.equal(data.reasonText(new api.DashboardAPIError("ANNOTATIONS_CHANGED", 409), L), "다른 사람이 먼저 바꿨습니다. 새로 불러온 내용에서 다시 적용하세요.");
  assert.equal(data.reasonText(new api.DashboardAPIError("TEXT_CONTAINS_CREDENTIAL", 422), L).startsWith("비밀값으로 보이는"), true);
  assert.equal(data.reasonText(new api.DashboardAPIError("nope", 403), L), "이 작업을 할 권한이 없습니다.");
  assert.equal(data.reasonText(new Error("network"), L), "서버에 연결하지 못했습니다.");
});

test("badges keep the design's classes", () => {
  assert.match(html(React.createElement(ui.RiskTag, { level: "critical" })), /class="risk risk-critical"[^>]*>.*심각/);
  assert.match(html(React.createElement(ui.StatusTag, { status: "action" })), /class="st st-action">조치 중/);
  assert.match(html(React.createElement(ui.StatusTag, { status: null })), /class="st st-none">노출 없음/);
  assert.match(html(React.createElement(ui.VerifyTag, { state: "revoked" })), /class="vchip v-revoked">폐기 확인/);
  assert.match(html(React.createElement(ui.VerifyTag, { state: "expired" })), /class="vchip v-inactive">만료됨/);
  assert.match(html(React.createElement(ui.Donut, { segments: [{ value: 1, color: "red" }, { value: 3, color: "gray" }], center: "4" })), /stroke-dasharray/);
});

test("the credential panel shows masked values only and escapes what people typed", () => {
  const tabs = load("@/console/views/credentials/tabs.tsx");
  const list = load("@/console/views/credentials/cells.tsx");
  const secret = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4";
  const c = row({ name: "<b>deploy</b>", scopes: [{ name: "repo", write: true }] });
  const detail = { id: "f-1", workflow_status: "OPEN", exposures: [{ id: "e-1", source_type: "github", resource_name: "acme/app", location: "config/prod.yml", line_number: 4,
    redacted_line: "token: ••••", status: "OPEN", first_seen_at: "2026-09-20T00:00:00Z", metadata: { exposure: "public" } }],
    events: [{ id: "v1", actor: "00000000-0000-0000-0000-000000000001", event_type: "COMMENT", note: "<script>x</script>", created_at: "2026-09-26T00:00:00Z" },
      { id: "v2", actor: "scanner", event_type: "ROLLUP_UPDATED", note: "EXPOSURE_ROLLUP_REPAIRED", created_at: "2026-09-25T00:00:00Z" }], credential: {} };
  const overview = html(React.createElement(tabs.OverviewTab, { c, detail, name: c.name }));
  assert.match(overview, /token: ••••/);
  assert.match(overview, /비공개 저장소 전체 읽기·쓰기/);
  assert.doesNotMatch(overview, new RegExp(secret));
  assert.doesNotMatch(overview, /<b>deploy<\/b>/);
  const history = html(React.createElement(tabs.HistoryTab, { c, detail, typeName: "GitHub 토큰" }));
  assert.match(history, /코멘트 · &lt;script&gt;x&lt;\/script&gt;/);
  assert.match(history, /노출 집계 갱신/);
  assert.doesNotMatch(history, /EXPOSURE_ROLLUP_REPAIRED/);
  assert.match(history, /로컬 관리자/);
  const items = risk.remediationFor(c, L);
  const remed = html(React.createElement(tabs.RemedTab, { c, items, name: c.name, canEdit: false, onComment: () => {} }));
  assert.match(remed, /&lt;b&gt;deploy&lt;\/b&gt;/);
  assert.doesNotMatch(remed, /<b><b>deploy/);
  assert.match(html(React.createElement(list.Expiry, { c: row({ expiry: "none" }) })), /class="exp-none"[^>]*>없음/);
  assert.match(html(React.createElement(list.Expiry, { c: row({ expiry: "unknown" }) })), /미확인/);
});

/* ---------- integrations ---------- */

const model = load("@/console/views/integrations/model.ts");
const copy = load("@/console/views/integrations/copy.ts");
const logos = load("@/console/logos.tsx");
const plain = value => JSON.parse(JSON.stringify(value));
const option = id => ({ id, label: id, label_ko: id });
const GITLAB = {
  provider: "gitlab", label: "GitLab", label_ko: "GitLab", category: "code",
  editions: [option("cloud"), { ...option("self_managed"), origin: true }],
  target: [
    { name: "host", label: "Host", label_ko: "서버 주소", kind: "url", required: true, editions: ["self_managed"] },
    { name: "scope", label: "Scope", label_ko: "범위", kind: "choice", default: "group", options: [option("group"), option("project"), option("instance")] },
    { name: "id", label: "Group or project ID", label_ko: "그룹 또는 프로젝트 ID", kind: "id", required: true, when: { scope: ["group", "project"] } },
    { name: "mounts", label: "Mounts", label_ko: "마운트", kind: "list" },
  ],
  purposes: {
    exposure: { permissions: [{ id: "read_repository", label: "Read", label_ko: "읽기" }] },
    inventory: { permissions: [{ id: "read_api", label: "API", label_ko: "API" }, { id: "instance_admin", label: "Admin", label_ko: "관리자", when: { scope: ["instance"] } }],
      plan: [{ name: "schedule_minutes", label: "Every", label_ko: "주기", kind: "number", default: 1440 },
        { name: "deploy_keys", label: "Deploy keys", label_ko: "배포 키", kind: "bool", default: false, when: { scope: ["project"] } }] },
    identity: { permissions: [{ id: "admin_org", label: "Org", label_ko: "조직", methods: ["pat"] }] },
  },
  auth_methods: [
    { id: "token", label: "Token", label_ko: "토큰", renewal: "EXPIRES", purposes: ["exposure", "inventory"], fields: [{ name: "token", label: "Token", label_ko: "토큰", kind: "secret", secret: true }] },
    { id: "pat", label: "PAT", label_ko: "PAT", renewal: "EXPIRES", purposes: ["identity"], advanced: true },
  ],
};

test("the wizard applies the catalog's field, permission and method rules as the server does", () => {
  const values = model.defaults(GITLAB.target);
  assert.deepEqual(plain(model.targetFields(GITLAB, "cloud", values).map(f => f.name)), ["scope", "id", "mounts"]);
  assert.deepEqual(plain(model.targetFields(GITLAB, "self_managed", { ...values, scope: "instance" }).map(f => f.name)), ["host", "scope", "mounts"]);
  const fields = model.targetFields(GITLAB, "cloud", values);
  assert.deepEqual(plain(model.payload(fields, { ...values, id: " 42 ", mounts: "secret, team-a  kv" })), { scope: "group", id: "42", mounts: ["secret", "team-a", "kv"] });
  assert.equal(model.missingRequired(fields, values).name, "id");
  assert.equal(model.missingRequired(fields, { ...values, id: "42" }), undefined);
  assert.equal(model.combinable(GITLAB, ["inventory"], "exposure", "cloud"), true);
  assert.equal(model.combinable(GITLAB, ["inventory"], "identity", "cloud"), false);
  assert.deepEqual(plain(model.permissionsFor(GITLAB, "inventory", "token", { scope: "group" }).map(p => p.id)), ["read_api"]);
  assert.deepEqual(plain(model.permissionsFor(GITLAB, "inventory", "token", { scope: "instance" }).map(p => p.id)), ["read_api", "instance_admin"]);
  assert.deepEqual(plain(model.permissionsFor(GITLAB, "identity", "token", {}).map(p => p.id)), []);
  assert.deepEqual(plain(model.planFields(GITLAB, "inventory", "cloud", { scope: "project" }).map(f => f.name)), ["schedule_minutes", "deploy_keys"]);
  assert.deepEqual(plain(model.payload(model.planFields(GITLAB, "inventory", "cloud", { scope: "group" }), { schedule_minutes: "360" })), { schedule_minutes: 360 });
});

test("GCP plans keep value reading but never offer or resend a legacy value storage choice", () => {
  // Only the plan fields this normalization regression exercises; the provider's real descriptor is covered by Python.
  const plan = [{ name: "schedule_minutes", kind: "number", default: 1440 }, { name: "read_values", kind: "bool", default: false }];
  const gcp = { purposes: { inventory: { plan }, vault: { plan } } };
  for (const purpose of ["inventory", "vault"]) {
    const fields = model.planFields(gcp, purpose, "cloud", { scope: "project", project: "acme-prod" }, true);
    assert.ok(fields.some(field => field.name === "read_values" && field.default === false));
    assert.ok(fields.every(field => field.name !== "keep_values"));
    const values = model.valuesOf(fields, { read_values: true, keep_values: true, schedule_minutes: 60 });
    const body = plain(model.payload(fields, values));
    assert.equal(body.read_values, true);
    assert.equal(body.schedule_minutes, 60);
    assert.ok(!("keep_values" in body) && !("store_values" in body));
  }
  const wizard = source("@/console/views/integrations/wizard.tsx");
  assert.doesNotMatch(wizard, /keep_values|kept encrypted|암호화해 보관/);
  assert.match(wizard, /Raw values are never stored; only HMAC fingerprints are kept/);
});

test("a connection's state comes from its records' health and its permission check", () => {
  const soon = new Date(NOW + 6 * day).toISOString();
  const conn = (changes = {}) => ({ id: "c1", provider: "gitlab", edition: "cloud", name: "GitLab · 42", status: "ACTIVE", revision: 1, purposes: ["inventory"],
    target: { scope: "group", id: "42" }, plans: { inventory: {} }, auth_method: "token", renewal: "EXPIRES", credential: { roles: ["credential"], reference: false },
    checks: { results: {}, checked_at: null, requested_at: null, job_id: null, stale: false, error: null },
    children: [{ kind: "metadata", id: "m1", purpose: "inventory" }, { kind: "content", id: "s1", purpose: "exposure" }, { kind: "aws_account", id: "a1", purpose: "vault" }], ...changes });
  const item = (changes = {}) => ({ key: "coverage:m1", kind: "METADATA", id: "m1", provider: "gitlab", name: "x", auth_state: "READY", auth_reason: null,
    expires_at: null, expiry_stage: "NONE", last_success_at: "2026-09-26T00:00:00Z", last_failure_at: null, last_failure_code: null, last_status: "COMPLETE", freshness: "FRESH", ...changes });
  assert.deepEqual(plain(model.healthOf(conn(), [item(), item({ key: "content:s1" }), item({ key: "aws_account:a1" }), item({ key: "coverage:other" })]).map(i => i.key)),
    ["coverage:m1", "content:s1", "aws_account:a1"]);
  assert.equal(model.rowState(conn(), [item()], L, NOW).tone, "ok");
  const expiring = model.rowState(conn(), [item({ auth_state: "EXPIRING", expires_at: soon })], L, NOW);
  assert.equal(expiring.tone, "warn"); assert.match(expiring.note, /6일 뒤 만료/); assert.equal(expiring.fix, "reauth");
  assert.equal(model.rowState(conn(), [item({ auth_state: "REAUTH_REQUIRED", auth_reason: "AUTH_EXPIRED" })], L, NOW).note, "인증이 만료됐습니다");
  const limited = model.rowState(conn(), [item({ auth_state: "PERMISSION_LIMITED" })], L, NOW);
  assert.equal(limited.tone, "partial"); assert.equal(limited.fix, "logs");
  assert.equal(model.rowState(conn(), [item({ last_success_at: null, last_status: "NOT_COLLECTED" })], L, NOW).tone, "running");
  assert.equal(model.rowState(conn({ status: "DISABLED" }), [], L, NOW).tone, "off");
  assert.equal(model.rowState(conn({ status: "DRAFT", plans: {} }), [], L, NOW).fix, "resume");
  const missing = { inventory: { status: "MISSING", items: [{ permission: "read_api", status: "MISSING", detail: "HTTP_403" }] } };
  const checked = { results: missing, checked_at: "2026-09-26T00:00:01Z", requested_at: "2026-09-26T00:00:00Z", job_id: "j", stale: false, error: null };
  assert.match(model.rowState(conn({ status: "CHECKED", plans: {}, checks: checked }), [], L, NOW).note, /권한 1개가 없습니다/);
  assert.equal(model.rowState(conn({ checks: checked }), [item()], L, NOW).fix, "recheck");
  assert.equal(model.rowState(conn({ checks: { ...checked, checked_at: null } }), [item()], L, NOW).tone, "running");
  assert.equal(model.checked(conn({ checks: { ...checked, stale: true } })), false);
  assert.equal(model.checkSummary(model.checkItems(conn({ checks: checked }))), "missing");
  assert.match(model.detailText("HTTP_403", L), /조회가 거절.*권한·리소스 공유·조직 정책/);
  assert.match(model.detailText("AWS_REGIONS_ACCESS_DENIED", L), /ec2:DescribeRegions/);
  assert.match(model.detailText("HTTP_401", L), /다시 인증/);
  assert.match(model.detailText("HTTP_429", L), /잠시 뒤/);
  assert.equal(model.detailText("CUSTOMER_CLI_REPORTS_ON_UPLOAD", L), "CLI가 업로드할 때 확인");
  // A templated role's value reads are named for what the template does, never as advice the check cannot confirm.
  assert.match(model.detailText("AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES", L), /템플릿.*GetParametersByPath.*경로를 비우고/);
  assert.match(model.detailText("AWS_SCANNER_ROLE_DENIES_SECRET_VALUES", L), /템플릿.*GetSecretValue.*금고 대조를 빼고/);
  assert.match(model.detailText("VALUE_READER_POLICY_DENIES", L), /VaultSecretArns·VaultParameterPathArns/);
  assert.match(model.detailText("AWS_PARAMETER_PATH_INVALID", L), /영문·숫자와 \. _ - 만/);
  // An explicit deny is not fixed by a stack list; a schedule waits for the installation's AWS automatic collection.
  assert.match(model.detailText("VALUE_READER_POLICY_EXPLICITLY_DENIED", L), /권한 경계.*SCP.*풀리지 않으므로/);
  assert.match(model.detailText("VALUE_READER_AUTOMATION_DISABLED", L), /AWS 자동 수집 설정이 이 계정을 포함할 때만/);
  assert.match(model.detailText("AWS_VALUE_READER_POLICY_TOO_LARGE", L), /10,240자/);
});

test("the AWS value-reader fields wait for the value-reader switch", () => {
  assert.equal(model.idleReaderField("aws", "vault", "secret_arns", {}), true);
  assert.equal(model.idleReaderField("aws", "vault", "secret_arns", { value_reader: true }), false);
  assert.equal(model.idleReaderField("aws", "vault", "ssm_prefixes", {}), false);
  assert.equal(model.idleReaderField("gcp", "vault", "secret_arns", {}), false);
});

test("inventory types follow the target, and a bound type switches through its plan option", () => {
  const d = { ...GITLAB, purposes: { ...GITLAB.purposes, inventory: { ...GITLAB.purposes.inventory,
    plan: [...GITLAB.purposes.inventory.plan, { name: "sources", label: "Lists", label_ko: "목록", kind: "choices", when: { scope: ["instance"] }, options: [option("pat"), option("keys")] }],
    types: [
      { id: "pat", label: "PAT", label_ko: "PAT", support: "YYYYYYYYY", reasons: {}, plan: [{ always: true, when: { scope: ["group"] }, editions: ["cloud"] }, { field: "sources", option: "pat" }] },
      { id: "deploy_key", label: "Deploy key", label_ko: "배포 키", support: "YYYYYYYYY", reasons: {}, plan: [{ field: "deploy_keys" }, { field: "sources", option: "keys" }] },
      { id: "group_token", label: "Group token", label_ko: "그룹 토큰", support: "YYYYYYYYY", reasons: {}, when: { scope: ["group"] } },
    ] } } };
  const pick = (edition, target, values = {}) => {
    const fields = model.planFields(d, "inventory", edition, target);
    return plain(model.typeChoices(d, edition, target, fields, { ...model.defaults(fields), ...values }).map(c => [c.type.id, c.on, c.field?.name ?? null]));
  };
  assert.deepEqual(pick("cloud", { scope: "group" }), [["pat", true, null], ["group_token", true, null]]);
  assert.deepEqual(pick("self_managed", { scope: "group" }), [["group_token", true, null]]);
  assert.deepEqual(pick("cloud", { scope: "project" }), [["deploy_key", false, "deploy_keys"]]);
  assert.deepEqual(pick("self_managed", { scope: "instance" }, { sources: ["pat"] }), [["pat", true, "sources"], ["deploy_key", false, "sources"]]);
  const fields = model.planFields(d, "inventory", "self_managed", { scope: "instance" });
  const choices = model.typeChoices(d, "self_managed", { scope: "instance" }, fields, { sources: ["pat"] });
  assert.deepEqual(plain(model.switchType(choices[1], { sources: ["pat"] }, true)), { sources: ["pat", "keys"] });
  assert.deepEqual(plain(model.switchType(choices[0], { sources: ["pat"] }, false)), { sources: [] });
  assert.deepEqual(plain([...model.typeFields(choices, fields)]), ["sources"]);
  const project = model.planFields(d, "inventory", "cloud", { scope: "project" });
  assert.deepEqual(plain(model.switchType(model.typeChoices(d, "cloud", { scope: "project" }, project, { deploy_keys: false })[0], { deploy_keys: false }, true)), { deploy_keys: true });
  const listed = { type: d.purposes.inventory.types[1], field: { name: "accounts", label: "Accounts", label_ko: "계정", kind: "list" }, on: false };
  assert.equal(model.switchable(listed), false);
  const scanning = { ...d, purposes: { exposure: { scans: [{ id: "files", label: "Files", label_ko: "파일" }, { id: "wiki", label: "Wiki", label_ko: "위키", editions: ["cloud"] }] } } };
  assert.deepEqual(plain(model.scansFor(scanning, "self_managed").map(s => s.id)), ["files"]);
  assert.deepEqual(plain(model.valuesOf(project, { deploy_keys: true, schedule_minutes: 60 })), { schedule_minutes: "60", deploy_keys: true });
});

test("an exposure scope reads where the connection scans and counts the places it keeps", () => {
  const scope = load("@/console/views/integrations/scope.ts");
  const conn = (changes = {}) => ({ id: "c1", provider: "gitlab", plans: { exposure: {} }, children: [
    { kind: "content", id: "s1", purpose: "exposure", source_type: "gitlab", name: "GitLab · group" },
    { kind: "metadata", id: "m1", purpose: "inventory" }], ...changes });
  assert.deepEqual(plain(scope.scopeTargets(conn())), [{ kind: "source", id: "s1", sourceType: "gitlab", name: "GitLab · group" }]);
  assert.deepEqual(plain(scope.scopeTargets(conn({ plans: { inventory: {} } }))), []);
  const aws = conn({ provider: "aws", children: [{ kind: "aws_account", id: "a1", purpose: "inventory", account_id: "000000000000" }] });
  assert.deepEqual(plain(scope.scopeTargets(aws)), [{ kind: "aws", id: "a1", sourceType: "s3", name: "000000000000" }]);
  const profile = (roots, excluded = []) => ({ selected_roots: roots.map(resource_id => ({ resource_id })), excluded_ids: excluded });
  assert.equal(scope.scopedCount([profile(["a", "b", "c"], ["c"]), profile(["b", "d"])]), 3);
  assert.deepEqual(plain(scope.splitPatterns(" platform/*, data/x\nweb ,")), ["platform/*", "data/x", "web"]);
  assert.equal(scope.unitOf("s3", L), "버킷");
  assert.equal(scope.unitOf("notion", L), "페이지");
  assert.equal(scope.unitOf("github", L), "저장소");
  // A website is its domains, with no account behind it.
  assert.equal(scope.unitOf("website", L), "사이트");
  assert.equal(scope.everythingOf("website", L), "연동한 도메인 전체");
  assert.equal(scope.everythingOf("github", L), "연동 계정이 볼 수 있는 전체");
});

test("CreMore's AWS identity: who may approve it and what a refusal means", () => {
  const identity = load("@/console/views/integrations/aws-identity.tsx");
  const view = extra => ({ api: { state: "READY", kind: "IAM_ROLE", requires: null }, worker: null, sign_in: null, worker_stale: false,
    same_identity: true, approvable: null, approved: null, hold: null, policy: {}, permission_set_policy: null, ...extra });
  assert.deepEqual(JSON.parse(JSON.stringify(identity.approval(view({}), true))), { needs: null, offered: true });
  assert.equal(identity.approval(view({}), false).offered, false);
  // Approved already: offered again only when CreMore runs as another identity, or the approval came from a setting.
  const approved = { kind: "IAM_ROLE", account_id: "111111111111", source: "API" };
  assert.equal(identity.approval(view({ approved }), true).offered, false);
  assert.equal(identity.approval(view({ approved, hold: "AWS_SCANNER_IDENTITY_CHANGED" }), true).offered, true);
  assert.equal(identity.approval(view({ approved: { ...approved, source: "SETTING" } }), true).offered, true);
  // A role whose exact ARN is unknown asks for it; root credentials are never offered.
  const role = identity.approval(view({ approvable: "ROLE_ARN_REQUIRED", api: { state: "READY", kind: "IAM_ROLE", requires: "ROLE_ARN" } }), true);
  assert.equal(role.needs, "ROLE_ARN");
  assert.equal(role.offered, true);
  assert.equal(identity.approval(view({ approvable: "ROOT_CREDENTIALS_REFUSED", api: { state: "READY", kind: "ROOT" } }), true).offered, false);
  assert.equal(identity.refusalText("WORKER_IDENTITY_MISMATCH: the API and worker run as different AWS identities", L),
    "API와 워커가 서로 다른 AWS 신원으로 실행 중입니다. 같은 로그인을 쓰도록 맞추세요.");
  assert.equal(identity.refusalText("WORKER_LOGIN_REQUIRED: the worker process cannot sign in to AWS", L), "워커 프로세스가 AWS에 로그인하지 못했습니다.");
  assert.equal(identity.refusalText("ROLE_ARN_REQUIRED: the API process cannot use this AWS identity", L), "이 신원이 쓰는 IAM 역할의 전체 ARN을 입력하세요.");
  assert.equal(identity.kindName("IDENTITY_CENTER", "CreMoreScanner", L), "IAM Identity Center · CreMoreScanner");
  assert.equal(identity.kindName("IAM_USER", null, L), "IAM 사용자");
});

test("Korean particles follow the word's last sound", () => {
  assert.equal(text.josa("저장소", "은/는"), "저장소는");
  assert.equal(text.josa("버킷", "은/는"), "버킷은");
  assert.equal(text.josa("버킷", "을/를"), "버킷을");
  assert.equal(text.josa("페이지", "이/가"), "페이지가");
  assert.equal(text.josa("TFVC", "을/를"), "TFVC을(를)");
});

test("refusals, names and results read in the reader's words", () => {
  assert.equal(model.onboardingText("TARGET_FIELD_REQUIRED:id", GITLAB.target, L), "그룹 또는 프로젝트 ID을(를) 입력하세요.");
  assert.equal(model.onboardingText("FIELD_INVALID:host", GITLAB.target, L), "서버 주소의 형식이 맞지 않습니다.");
  assert.equal(model.onboardingText("AWS_SCANNER_IDENTITY_NOT_APPROVED", [], L), "먼저 CreMore가 쓸 AWS 신원을 승인하세요.");
  assert.equal(model.onboardingText("PURPOSE_ALREADY_ACTIVE:inventory", [], L), "이미 수집 중인 기능입니다.");
  assert.equal(model.onboardingText("PURPOSE_NOT_ACTIVE:vault", [], L), "아직 수집하지 않는 기능입니다. 먼저 시작하세요.");
  assert.equal(model.onboardingText("PROVIDER_CONNECTION_NOT_ACTIVE", [], L), "수집 중인 연동에서만 수집 설정을 바꿀 수 있습니다.");
  assert.match(model.onboardingText("GITLAB_ID_INVALID", [], L), /GITLAB_ID_INVALID/);
  assert.equal(model.onboardingText("SOMETHING_ELSE", [], L), null);
  assert.equal(model.shortName(GITLAB, { name: "GitLab · group", target: { scope: "group", id: "42" } }), "42");
  assert.equal(model.shortName(GITLAB, { name: "Platform GitLab", target: { scope: "group", id: "42" } }), "Platform GitLab");
  assert.equal(model.shortName({ ...GITLAB, target: [] }, { name: "GitLab · GitLab.com", target: {} }), "");
  const rows = [row({ issued: { entity_id: null, provider: "aws_iam", origin: "", tenant: "", object_id: "", observed_at: null }, provider: "aws" }),
    row({ exposures: [{ ...row().exposures[0], source_type: "s3" }] }), row()];
  assert.equal(model.inventoryCount(undefined, { provider: "aws", target: {} }, rows), 1);
  assert.equal(model.exposureCount("aws", rows), 1);
  assert.equal(model.exposureCount("github", rows), 2);
  assert.equal(model.scheduleLabel(360, L), "6시간마다");
  assert.equal(model.scheduleLabel(120, L), "2시간마다");
  assert.equal(copy.methodShort({ id: "customer_cli", label: "", label_ko: "" }, L), "고객 CLI");
  assert.match(copy.methodHint("vault", { id: "customer_cli", renewal: "NONE", purposes: ["vault"] }, L), /수집기 토큰을 한 번/);
  assert.equal(copy.renewalTag({ id: "token", renewal: "EXPIRES", purposes: [] }, L).text, "만료일 관리");
});

test("risk score evidence reads as words, never as model codes", () => {
  const typeName = type => labels.typeLabel(type, L);
  const line = risk.scoreLine("exploitability 2/35 verification_not_attempted", L, typeName);
  assert.deepEqual(plain(line), { dimension: "악용 가능성", points: "2/35", text: "유효성 검증을 하지 않음" });
  assert.equal(risk.scoreLine("exposure 7/15 internal_plaintext_exposure_multiple_occurrences", L, typeName).text, "내부 위치에 평문으로 노출 · 여러 곳");
  assert.match(risk.scoreLine("credential_impact 30/30 credential_type_aws_access_key", L, typeName).text, / 유형$/);
  assert.doesNotMatch(risk.scoreLine("credential_impact 30/30 credential_type_aws_access_key", L, typeName).text, /_/);
  assert.equal(risk.missingEvidence("PROVIDER_VALIDITY_NOT_CONFIRMED", L), "발급 서비스의 유효성 확인");
  assert.equal(risk.missingEvidence("new_code_here", L), "new code here");
});

test("a token type's key metadata comes from its declaration and the values from collected rows", () => {
  const metadata = load("@/console/views/metadata.tsx");
  const type = { id: "classic_pat", label: "Classic PAT", support: "YYPYYYYYP", reasons: {} };
  assert.deepEqual(plain(metadata.counts(type)), { yes: 7, part: 2, no: 0 });
  assert.equal(metadata.stateAt(type, 2), "part");
  assert.equal(metadata.stateAt({ ...type, support: "YY" }, 5), "no");
  const issued = { entity_id: null, provider: "github", origin: "", tenant: "", object_id: "inventory:77", observed_at: null, type: "classic_pat" };
  const listed = row({ exposed: false, exposures: [], hint: null, name: "deploy bot", issued, created_at: "2026-09-01T00:00:00Z", expiry: "none",
    scopes: [{ name: "repo" }, { name: "workflow" }], issuer: { name: "octocat" } });
  assert.equal(metadata.valueOf(listed, "id", L, "ko"), "77");
  assert.equal(metadata.valueOf(row({ issued }), "id", L, "ko"), "77");
  const aws = { ...issued, provider: "aws_iam", object_id: "AKIAIOSFODNN7EXAMPLE" };
  assert.equal(metadata.valueOf(row({ issued: aws, hint: "AKIA••••••••MPLE" }), "id", L, "ko"), "AKIA••••••••MPLE");
  assert.equal(metadata.valueOf(listed, "expires", L, "ko"), "만료일 없음");
  assert.equal(metadata.valueOf(listed, "scopes", L, "ko"), "repo, workflow");
  assert.equal(metadata.valueOf(listed, "creator", L, "ko"), null); // owner is not creator
  assert.equal(metadata.valueOf({ ...listed, issued: { ...issued, creator_name: "app-admin" } }, "creator", L, "ko"), "app-admin");
  assert.equal(metadata.valueOf(listed, "last_used", L, "ko"), null);
  assert.equal(metadata.valueOf(listed, "state", L, "ko"), null);
});

test("every brand logo is the brand's own file; what is not a brand is a line icon", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const files = new Set(fs.readdirSync(path.join(__dirname, "..", "public", "logos")));
  const brands = load("@/console/logo-set.ts").BRANDS;
  for (const id of Object.keys(brands)) assert.ok(files.has(`${id}.svg`), `${id}.svg is missing`);
  assert.equal(logos.markOf("stripe").src, "/logos/stripe.svg");
  assert.equal(logos.markOf("vault").solid, true);
  assert.equal(logos.markOf("azure_key_vault").name, "Azure Key Vault");
  assert.equal(logos.markOf("azure_entra").src, "/logos/entra_id.svg");
  assert.equal(logos.markOf("external_vault").glyph, "vault");
  assert.equal(logos.markOf("not-a-service"), null);
  assert.equal(logos.serviceName("aws_iam"), "AWS");
  assert.equal(logos.serviceName("hashicorp"), "HashiCorp");
  for (const id of ["gitlab", "github", "aws", "gcp", "notion", "slack", "okta", "keycloak", "openbao", "azure", "azure_devops", "entra_id", "atlassian",
    "google_workspace"]) {
    assert.ok(logos.markOf(id)?.src, `${id} has an image logo`);
  }
  assert.ok(files.has("google_workspace.png"));  // the G that workspace.google.com uses as its own icon (SOURCES.md)
});

test("a name or an email reads as the person the IdP names, with an address to write to", () => {
  const people = load("@/console/people.ts");
  const list = [
    { id: "1", name: "김데모", email: "kim.demo@example.com", department: "플랫폼팀", title: null, state: "ACTIVE", sources: [] },
    { id: "2", name: "Bob", email: null, department: null, title: null, state: "DEPARTED", sources: [] },
  ];
  assert.equal(people.personOf(list, " KIM.DEMO@example.com ").name, "김데모");
  assert.equal(people.personOf(list, "bob").id, "2");
  assert.equal(people.personOf(list, "nobody"), undefined);
  assert.equal(people.personOf(undefined, "김데모"), undefined);
  assert.deepEqual(JSON.parse(JSON.stringify(people.addressesOf(list, ["김데모", "Bob", "x@example.com", "kim.demo@example.com"]))),
    ["x@example.com", "kim.demo@example.com"]);
});

/* ---------- a finding's context: CODEOWNERS, last authors and who can read the repository ---------- */

const CONTEXT = {
  status: "COMPLETE", collected_at: "2026-09-27T00:00:00Z", reasons: [], locations: ["app", "api"].map(name => ({ exposure_id: name, access_key: name, source_connection_id: "connection-1", source_type: "github", repository: `acme/${name}`, path: "file.env", context_status: "OBSERVED" })),
  repositories: [
    { access_key: "app", source_connection_id: "connection-1", source_type: "github", repository: "acme/app", status: "OBSERVED", basis: "GITHUB_REPOSITORY_COLLABORATORS", truncated: false,
      people: [{ login: "kim-demo", name: "김데모", role: "admin" }, { login: "=cmd", name: null, role: "write" }] },
    { access_key: "api", source_connection_id: "connection-1", source_type: "github", repository: "acme/api", status: "OBSERVED", basis: "GITHUB_REPOSITORY_COLLABORATORS", truncated: false,
      people: [{ login: "Kim-Demo", name: "김데모", role: "write" }] },
  ],
};

test("a CSV cell never runs as a spreadsheet formula", () => {
  assert.equal(text.csvText([["=1+1", "+x", "-2", "@a", "plain", "say \"hi\"", "a,b", null]]), "'=1+1,'+x,'-2,'@a,plain,\"say \"\"hi\"\"\",\"a,b\",");
  assert.equal(text.csvText([["a"], ["b"]]), "a\r\nb");
});

test("provider account observations retain each repository and export source identity", () => {
  const people = load("@/console/people.ts");
  assert.deepEqual(plain(people.accessPeople(CONTEXT).map(person => person.login)), ["kim-demo", "=cmd", "Kim-Demo"]);
  const rows = people.accessRows(CONTEXT);
  assert.ok(rows[0].includes("source_connection_id"));
  assert.ok(rows[0].includes("completeness"));
  assert.equal(rows.length, 4);
  assert.match(text.csvText(rows), /'=cmd,,write,UNKNOWN,GITHUB_REPOSITORY_COLLABORATORS/);
});

test("the owner tab lists who can read the repository and the row says where CODEOWNERS named the owner", () => {
  const tabs = load("@/console/views/credentials/tabs.tsx");
  const c = row({ owner: { name: "@kim-demo", team: null, basis: "CODEOWNERS", where: "acme/app · CODEOWNERS" },
    access: { count: 2, truncated: false, basis: "GITHUB_REPOSITORY_COLLABORATORS", repository: "acme/app", collected_at: "2026-09-27T00:00:00Z" } });
  assert.equal(risk.ownerBasis(c, L), "CODEOWNERS · acme/app · CODEOWNERS");
  const props = { c, targets: [], canEdit: true, onAssign: () => {}, onContact: () => {}, onNotify: () => {} };
  const analyst = html(React.createElement(tabs.OwnerTab, { ...props, context: CONTEXT, onRecheck: () => {} }));
  assert.match(analyst, /근거: CODEOWNERS · acme\/app · CODEOWNERS/);
  assert.match(analyst, />김데모</);
  assert.match(analyst, />=cmd</);
  assert.match(analyst, /발견 위치 2곳 · 주체 관측 3건/);
  assert.match(analyst, /알림 보내기/);
  assert.match(analyst, /aria-label="다시 확인"/);
  // A viewer reads the count the row carries, never the names.
  const viewer = html(React.createElement(tabs.OwnerTab, { ...props, canEdit: false }));
  assert.match(viewer, /acme\/app · 이전 요약 2건/);
  assert.doesNotMatch(viewer, /알림 보내기|김데모/);
  // Nothing read yet, or a list the connected account may not read.
  assert.match(html(React.createElement(tabs.OwnerTab, { ...props, c: row() })), /발견 위치별 접근 목록<\/div><div class="meta">확인하지 못했습니다/);
  const refused = { ...CONTEXT, status: "PARTIAL", repositories: [{ source_type: "github", repository: "acme/app", status: "FORBIDDEN", basis: "GITHUB_REPOSITORY_COLLABORATORS" }] };
  assert.match(html(React.createElement(tabs.OwnerTab, { ...props, c: row(), context: refused })), /저장소 구성원을 읽을 권한이 없습니다/);
  assert.deepEqual(plain(tabs.accessTargets(CONTEXT, L).map(target => target.name)), ["김데모", "=cmd", "김데모"]);
});

test("each exposed file shows who last changed it, and the cleanup goes to them", () => {
  const tabs = load("@/console/views/credentials/tabs.tsx");
  const graph = load("@/console/views/credentials/graph.tsx");
  const base = row();
  const c = row({ exposures: [{ ...base.exposures[0], author: "Lee Demo" }],
    access: { count: 300, truncated: true, basis: "GITLAB_PROJECT_MEMBERS", repository: "acme/app", collected_at: null } });
  const overview = html(React.createElement(tabs.OverviewTab, { c, name: "deploy" }));
  assert.match(overview, /<dt>작성자<\/dt>/);
  assert.match(overview, /Lee Demo/);
  assert.deepEqual(plain(risk.remediationFor(c, L).find(item => item.id === "cleanup").people), ["Lee Demo"]);
  const map = html(React.createElement(graph.AccessGraph, { c, view: "exposure", big: false, zoom: 1, name: "deploy" }));
  assert.match(map, /300\+개 접근 관련 주체/);
});

/* ---------- action approvals ---------- */

const LOCAL = "00000000-0000-0000-0000-000000000001";
function plan(changes = {}) {
  return { id: "p-1", credential_id: "c-1", account_id: "123456789012", user_name: "ci-deployer", principal_arn: "arn:aws:iam::123456789012:user/ci-deployer",
    identifier_hint: "AKIA••••1234", action_type: "DISABLE_ACCESS_KEY", status: "PENDING_APPROVAL", reason_code: "EXPOSURE_CONTAINMENT", plan_hash: "a".repeat(64),
    requested_by: LOCAL, requested_at: new Date(NOW - 3_600_000).toISOString(), expires_at: new Date(NOW + day).toISOString(),
    readiness: { status: "READY_FOR_APPROVAL", reasons: [], confirmed_consumers: 1, declared_consumers: 1, execution_gate_passed: true }, ...changes };
}

test("who may approve, execute, recheck or cancel a key plan follows the server's rules", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const local = { execution_enabled: false, single_operator: true, auth_mode: "local", supported_action: "DISABLE_ACCESS_KEY", supported_actions: ["DISABLE_ACCESS_KEY"] };
  const oidc = { ...local, single_operator: false, auth_mode: "oidc", execution_enabled: true };
  const admin = { id: LOCAL, role: "Admin" };
  // A single operator approves their own plan; OIDC needs a different Admin.
  assert.equal(approvals.planPermissions(plan(), local, admin, L, NOW).approve, true);
  const own = approvals.planPermissions(plan(), oidc, admin, L, NOW);
  assert.equal(own.approve, false);
  assert.match(own.why, /다른 관리자/);
  assert.equal(approvals.planPermissions(plan(), oidc, { id: "other", role: "Admin" }, L, NOW).approve, true);
  assert.equal(approvals.planPermissions(plan(), oidc, { id: "other", role: "Remediator" }, L, NOW).approve, false);
  // An incomplete review blocks approval; the reason reads in words.
  const incomplete = approvals.planPermissions(plan({ readiness: { status: "INCOMPLETE", reasons: ["CHANGE_WINDOW_NOT_CURRENT"], execution_gate_passed: false } }), oidc, { id: "other", role: "Admin" }, L, NOW);
  assert.equal(incomplete.approve, false);
  assert.match(incomplete.why, /운영 검토/);
  // Execution needs the installation switch and an approval by someone else (or a self-approval on a single operator).
  const approved = plan({ status: "APPROVED", approved_by: "other" });
  assert.equal(approvals.planPermissions(approved, local, admin, L, NOW).execute, false);
  assert.match(approvals.planPermissions(approved, local, admin, L, NOW).why, /실행이 꺼져/);
  assert.equal(approvals.planPermissions(approved, oidc, admin, L, NOW).execute, true);
  assert.equal(approvals.planPermissions(plan({ status: "APPROVED", approved_by: LOCAL }), oidc, admin, L, NOW).execute, false);
  // An expired plan cannot be approved; a plan whose write started cannot be cancelled.
  assert.equal(approvals.planStatus(plan({ expires_at: new Date(NOW - 1000).toISOString() }), NOW), "EXPIRED");
  assert.equal(approvals.planPermissions(plan({ status: "QUEUED", provider_write_started_at: new Date(NOW).toISOString() }), oidc, admin, L, NOW).cancel, false);
  assert.equal(approvals.planPermissions(plan({ status: "OUTCOME_UNKNOWN", approved_by: "other" }), oidc, admin, L, NOW).recheck, true);
});

test("a new plan's review is sent in ISO times, and a malformed one says what to fix", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
  const review = approvals.blankReview(NOW);
  assert.match(approvals.reviewBody(review, "DISABLE_ACCESS_KEY", L).problem, /UUID/);
  const filled = { ...review, scope_evidence_id: uuid(1), recovery_evidence_id: uuid(2),
    consumers: [{ ...review.consumers[0], consumer_id: uuid(3), owner_id: uuid(4), evidence_id: uuid(5) }] };
  const { body, problem } = approvals.reviewBody(filled, "DISABLE_ACCESS_KEY", L);
  assert.equal(problem, undefined);
  assert.match(body.window_start, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/);
  assert.equal("incident_id" in body, false);
  // Deletion needs its acknowledgement; a rotation declares consumers without dates.
  assert.match(approvals.reviewBody(filled, "DELETE_ACCESS_KEY", L).problem, /영구 삭제/);
  const rotation = approvals.reviewBody(filled, "PREPARE_ACCESS_KEY_ROTATION", L).body;
  assert.equal(rotation.consumers[0].transition, "PENDING");
  assert.equal(rotation.consumers[0].confirmed_at, "0001-01-01T00:00:00Z");
  // A consumer twice in one environment, or a window that ends first, is refused before sending.
  assert.match(approvals.reviewBody({ ...filled, consumers: [filled.consumers[0], filled.consumers[0]] }, "DISABLE_ACCESS_KEY", L).problem, /두 번/);
  assert.match(approvals.reviewBody({ ...filled, window_end: filled.window_start }, "DISABLE_ACCESS_KEY", L).problem, /종료/);
  assert.equal(approvals.validRotation("PUBLISH_ACCESS_KEY_ROTATION", { secret_arn: "arn:aws:secretsmanager:x", expected_current_version: "v".repeat(32) }), false);
});

test("tickets needing an independent Admin wait in approvals, and a kept actor reference reads short", () => {
  const approvals = load("@/console/views/approvals/model.ts");
  const ticket = { status: "WAITING_APPROVAL", playbook: { config: { approval_rule: "INDEPENDENT_ADMIN" } } };
  assert.equal(approvals.ticketNeedsApproval(ticket), true);
  assert.equal(approvals.ticketNeedsApproval({ ...ticket, internal_approval: { approved_by: "x", approved_at: "y" } }), false);
  assert.equal(approvals.ticketNeedsApproval({ ...ticket, playbook: { config: { approval_rule: "NONE" } } }), false);
  assert.equal(labels.actorLabel("bfa5d4ff-082f-5345-87c9-2bc60137869d", L), "사용자 bfa5d4ff");
});


test("IAM metadata distinguishes unavailable facts, issuer status and policy evidence", () => {
  const metadata = load("@/console/views/metadata.tsx");
  const type = { support: "YNYNPNYYY", reasons: { name: ["액세스 키에는 이름이 없습니다", "Access keys have no name"], creator: ["IAM이 만든 사람을 주지 않습니다", "IAM does not say who made it"] } };
  const issued = { provider: "aws_iam", current: true, last_used_status: "NO_INFORMATION", iam_policies: null };
  const c = row({ provider: "aws", issued, expiry: "none", name: "robot", issuer: { name: "robot" },
    verification: { state: "active", basis: "ISSUER_REPORTED" } });
  assert.equal(metadata.fieldDisplay(c, type, "expires", L, "ko"), "만료일 없음");
  assert.equal(metadata.fieldDisplay(c, type, "name", L, "ko"), "액세스 키에는 이름이 없습니다");
  assert.match(metadata.fieldDisplay(c, type, "creator", L, "ko"), /CloudTrail 미연결/);
  assert.equal(metadata.fieldDisplay(c, type, "owner", L, "ko"), "robot");
  assert.equal(metadata.fieldDisplay(c, type, "state", L, "ko"), "발급처 상태: 활성");
  assert.equal(ui.verifyLabel("active", L, "STS"), "활성 확인");
  for (const [status, reason] of Object.entries({ NO_INFORMATION: "사용 기록 없음 (IAM 조회)", DENIED: "마지막 사용 조회 권한 부족", FAILED: "마지막 사용 조회 실패", NOT_COLLECTED: "마지막 사용을 수집하지 않음" })) {
    c.issued.last_used_status = status;
    assert.equal(metadata.fieldDisplay(c, type, "last_used", L, "ko"), reason);
    if (status === "NO_INFORMATION") assert.match(risk.usageGap(c, L), /IAM 조회는 완료됐지만 마지막 사용 시각이 없습니다/);
    else assert.equal(risk.usageGap(c, L), reason);
    assert.equal(metadata.valueOf(c, "last_used", L, "ko"), null); // reason text is not a collected date
  }
  assert.equal(metadata.valueOf(c, "scopes", L, "ko"), null);
  assert.equal(metadata.fieldDisplay(c, type, "scopes", L, "ko"), "IAM 정책 미수집");
  const policies = load("@/console/views/credentials/permissions.tsx");
  for (const [status, expected] of [["DENIED", "IAM 정책 조회 권한 부족"], ["FAILED", "IAM 정책 조회 실패"], ["COMPLETE", "연결된 IAM 정책 없음"], ["PARTIAL", "IAM 정책 조회 일부 실패"]]) {
    c.issued.iam_policies = { status, policy_names: [], allow_actions: [], deny_statements: 0, conditional_statements: 0, permissions_boundary: false, truncated: false };
    assert.equal(metadata.fieldDisplay(c, type, "scopes", L, "ko"), expected);
    assert.match(html(React.createElement(policies.InventoryPermissions, { c })), new RegExp(expected));
  }
  c.issued.current = false;
  c.issued.iam_policies = { ...c.issued.iam_policies, policy_names: ["ReadObjects"], allow_actions: ["s3:GetObject"], conditional_statements: 1, truncated: true };
  const body = html(React.createElement(policies.InventoryPermissions, { c }));
  for (const text of ["과거 관측", "일부 조회", "표시 한도", "Allow 문장에 적힌 작업 · 1개", "조건부 문장 1개", "실제 접근 권한이 아닙니다"]) assert.ok(body.includes(text), text);
  assert.ok(!body.includes("s3:GetObject"), "actions stay collapsed until requested");
  c.issued.current = true;
  c.issued.iam_policies = { ...c.issued.iam_policies, status: "COMPLETE", truncated: false,
    policy_names: ["AdministratorAccess", "Billing", "AWSBillingConductorFullAccess", "AWSBillingConductorReadOnlyAccess", "AWSBillingReadOnlyAccess"] };
  assert.equal(metadata.fieldDisplay(c, type, "scopes", L, "ko"), "IAM 정책 5개");
  assert.equal(records.iamPolicyLabel(c, (_ko, en) => en), "5 IAM policies");
  const compact = html(React.createElement(policies.IAMPolicySummary, { c }));
  assert.match(compact, /aria-haspopup="dialog" aria-expanded="false"/);
  assert.ok(compact.includes("IAM 정책 5개"));
  for (const name of c.issued.iam_policies.policy_names) assert.ok(!compact.includes(name));
  assert.match(metadata.fieldDisplay(c, { support: "NNNNNNNNN", reasons: {} }, "created", L, "ko"), /현재 수집 경로에서 지원하지 않습니다/);
  // A partly supported field without a value says when it gets one; without a reason it says the provider gave none.
  const partly = { support: "YYYYPPNPP", reasons: { scopes: ["앱 권한 옵션을 켜면 보여 줍니다", "Shown with the app permission options on"] } };
  const bare = row({ provider: "azure", issued: { provider: "azure_entra" } });
  assert.equal(metadata.fieldDisplay(bare, partly, "scopes", L, "ko"), "앱 권한 옵션을 켜면 보여 줍니다");
  assert.equal(metadata.fieldDisplay(bare, { ...partly, reasons: {} }, "scopes", L, "ko"), "공급자가 값을 제공하지 않음");
});


test("AWS creator comes only from CloudTrail evidence, never the key owner", () => {
  const metadata = load("@/console/views/metadata.tsx");
  const c = row({ issued: { provider: "aws_iam", creator_status: "NOT_COLLECTED" }, issuer: { name: "key-owner" } });
  assert.equal(metadata.valueOf(c, "creator", L, "ko"), null);
  assert.match(records.creatorLabel(c, L), /아직 미수집/);
  c.issued.creator_status = "RUNNING";
  assert.equal(records.creatorLabel(c, L), "CloudTrail 수집 중");
  c.issued.creator_status = "NOT_OBSERVED_IN_WINDOW";
  assert.match(records.creatorLabel(c, L), /조회한 리전·기간/);
  c.issued.creator_status = "INCOMPLETE";
  assert.match(records.creatorLabel(c, L), /조회 미완료/);
  c.issued.creator_status = "CONFLICT";
  assert.match(records.creatorLabel(c, L), /충돌/);
  c.issued.creator = { arn: "arn:aws:iam::123456789012:user/key-creator", current: false, region: "us-east-1" };
  assert.equal(metadata.valueOf(c, "creator", L, "ko"), c.issued.creator.arn);
  assert.match(records.creatorLabel(c, L), /과거 수집 근거/);
  assert.equal(metadata.valueOf(c, "owner", L, "ko"), "key-owner");
  c.issued.creator.current = true;
  const cells = load("@/console/views/credentials/cells.tsx");
  for (const [resource, label] of [["user/team/key-creator", "key-creator"], ["root", "루트 계정"], ["assumed-role/Admin/session", "assumed-role/Admin/session"]]) {
    c.issued.creator.arn = `arn:aws:${resource.startsWith("assumed-role/") ? "sts" : "iam"}::123456789012:${resource}`;
    assert.equal(records.creatorLabel(c, L), label);
    const rendered = html(React.createElement(cells.CreatorSummary, { c }));
    assert.match(rendered, /aria-haspopup="dialog" aria-expanded="false"/);
    assert.ok(rendered.includes(label));
    assert.ok(!rendered.includes(c.issued.creator.arn));
  }
});

test("removal requires complete reconciliation and reappearance restores one active credential", () => {
  const original = row({ response: { state: "NEW", version: 0, current: null } });
  const partial = { ...original, exposures: [], exposure_state: "ACTIVE", all_locations_removed: false };
  assert.equal(records.isExposed(partial), true, "an empty incomplete listing is not removal");
  const removed = { ...original, exposure_state: "REMOVED", all_locations_removed: true,
    active_location_count: 0, removed_location_count: 1, response: { state: "REMOVED", version: 2, current: null } };
  assert.equal(records.isRemoved(removed), true);
  assert.equal(records.isOpen(removed), false);
  assert.equal(checks.stats([removed]).exposed, 0);
  assert.equal(checks.stats([removed]).open, 0);
  const again = { ...removed, exposure_state: "ACTIVE", all_locations_removed: false,
    response: { state: "NEEDS_ACTION", version: 3, current: null }, status: "done" };
  assert.equal(again.id, original.id, "one stable credential identity across scans");
  assert.equal(records.isExposed(again), true);
  assert.equal(records.isOpen(again), true, "old manual done cannot hide a confirmed recurrence");
  assert.equal(checks.stats([again]).action, 1);
  assert.equal(records.recordStatus({ ...again, status: "fp" }), "fp", "explicit triage remains separate");
});

test("a permission declared under two options stays in the check while either still needs it", () => {
  const d = { provider: "gcp", purposes: { inventory: {
    plan: [{ name: "service_account_iam", kind: "bool", default: false }, { name: "effective_access", kind: "bool", default: false }],
    permissions: [{ id: "resourcemanager.projects.getIamPolicy", option: "service_account_iam" },
      { id: "resourcemanager.projects.getIamPolicy", option: "effective_access" },
      { id: "iam.denypolicies.list", option: "effective_access" }] } } };
  const connection = { edition: "cloud", target: {}, purposes: ["inventory"], plans: { inventory: { effective_access: true } },
    checks: { results: { inventory: { items: [{ permission: "resourcemanager.projects.getIamPolicy", status: "MISSING" },
      { permission: "iam.denypolicies.list", status: "GRANTED" }] } } } };
  assert.equal(model.checkSummary(model.checkItems(connection, ["inventory"], d)), "missing");
  connection.plans.inventory = { effective_access: false };
  assert.deepEqual(model.checkItems(connection, ["inventory"], d).map(item => item.permission), []);
});
test("a permission one method needs and another reports itself is checked only for the method that needs it", () => {
  const d = { provider: "vault", purposes: { vault: { permissions: [
    { id: "kv_list", methods: ["token", "kubernetes"] }, { id: "kv_list", methods: ["customer_cli"], required: false }] } } };
  const conn = (auth_method, status) => ({ edition: "self_managed", target: {}, purposes: ["vault"], plans: { vault: {} }, auth_method,
    checks: { results: { vault: { items: [{ permission: "kv_list", status, detail: status === "NOT_REPORTED" ? "CUSTOMER_CLI_REPORTS_ON_UPLOAD" : undefined }] } } } });
  assert.equal(model.checkSummary(model.checkItems(conn("customer_cli", "NOT_REPORTED"), ["vault"], d)), "none");
  assert.equal(model.checkSummary(model.checkItems(conn("token", "MISSING"), ["vault"], d)), "missing");
});