// A GitHub App made from a manifest in the console: the manifest the browser posts carries only its own
// address added to what the API wrote, and the browser posts it only to an organization's "new App" page on the
// GitHub the connection names. Whose login is which person is read from one source, and the checklist counts its
// token scope only. Synthetic values only.
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { load } = require("./load-module.cjs");

const app = load("@/console/views/integrations/github-app.tsx");
const model = load("@/console/views/integrations/model.ts");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));

const edition = id => ({ id, label: id, label_ko: id });
const GH = {
  provider: "github", label: "GitHub", label_ko: "GitHub", category: "code",
  editions: [edition("cloud"), edition("enterprise_cloud"), edition("dedicated")],
  target: [{ name: "organization", label: "Organization", label_ko: "조직", kind: "name", required: true },
    { name: "enterprise", label: "Enterprise", label_ko: "엔터프라이즈", kind: "name", editions: ["enterprise_cloud", "dedicated"] }],
  purposes: { identity: {
    permissions: [{ id: "admin_org", label: "read:org", label_ko: "read:org", unless: "enterprise_identities" },
      { id: "read_enterprise", label: "read:enterprise", label_ko: "read:enterprise", option: "enterprise_identities" }],
    plan: [{ name: "enterprise_identities", kind: "bool", default: false, edition_defaults: { dedicated: true },
      editions: ["enterprise_cloud", "dedicated"], when: { enterprise: ["*"] }, label: "Enterprise", label_ko: "엔터프라이즈" }],
  } },
  auth_methods: [{ id: "token", label: "PAT", label_ko: "PAT", renewal: "EXPIRES", purposes: ["identity"], fields: [] }],
};

test("people come from the organization's SAML SSO or the enterprise's, and only that one's scope counts", () => {
  const named = { organization: "acme", enterprise: "acme-ent" };
  const ids = (edition, target, chosen = {}) => {
    const plan = { ...model.defaults(model.planFields(GH, "identity", edition, target)), ...chosen };
    return plain(model.permissionsFor(GH, "identity", "token", target, plan).map(permission => permission.id));
  };
  assert.deepEqual(ids("cloud", { organization: "acme" }), ["admin_org"]);  // no choice offered: the organization's
  assert.deepEqual(ids("enterprise_cloud", { organization: "acme" }), ["admin_org"]);
  assert.deepEqual(ids("enterprise_cloud", named), ["admin_org"]);
  assert.deepEqual(ids("enterprise_cloud", named, { enterprise_identities: true }), ["read_enterprise"]);
  assert.deepEqual(ids("dedicated", named), ["read_enterprise"]);  // GHE.com has managed users only
  // A choice made before the target lost its enterprise is neither counted nor sent: the wizard reads its choices
  // through the options this edition and target offer.
  const stale = model.valuesOf(model.planFields(GH, "identity", "enterprise_cloud", { organization: "acme" }), { enterprise_identities: true });
  assert.deepEqual(plain(stale), {});
  assert.deepEqual(plain(model.permissionsFor(GH, "identity", "token", { organization: "acme" }, stale).map(p => p.id)), ["admin_org"]);
  // A saved legacy plan without the choice still reads the organization, including on GHE.com.
  const conn = (edition, plan) => ({
    id: "g1", provider: "github", edition, name: "GitHub · acme", status: "ACTIVE", revision: 2, purposes: ["identity"],
    plans: { identity: plan }, auth_method: "token", credential: { roles: ["credential"], reference: false }, children: [], target: named,
    checks: { checked_at: "2026-10-02T02:00:00Z", requested_at: "2026-10-02T01:00:00Z", job_id: null, stale: false, error: null,
      results: { identity: { status: "MISSING", items: [{ permission: "admin_org", status: "MISSING" },
        { permission: "read_enterprise", status: "GRANTED" }] } } },
  });
  const counted = c => plain(model.checkItems(c, ["identity"], GH).map(item => item.permission));
  assert.deepEqual(counted(conn("enterprise_cloud", {})), ["admin_org"]);
  assert.deepEqual(counted(conn("enterprise_cloud", { enterprise_identities: true })), ["read_enterprise"]);
  assert.deepEqual(counted(conn("dedicated", {})), ["admin_org"]);
  assert.deepEqual(counted(conn("dedicated", { enterprise_identities: true })), ["read_enterprise"]);
});

// Drive the wizard's own handlers, as console-reach/console-stores do: hooks retain state, requests are fakes.
// The model-only assertions above cannot catch a wizard that keeps passing an old plan to the checklist.
function mountWizard(existing, descriptor = GH) {
  const hooks = [], sends = [], timers = [];
  let cursor = 0, effects = [], record = existing;
  const react = { ...React,
    useState(initial) {
      const index = cursor++;
      if (!(index in hooks)) hooks[index] = typeof initial === "function" ? initial() : initial;
      return [hooks[index], value => { hooks[index] = typeof value === "function" ? value(hooks[index]) : value; }];
    },
    useRef(value) { const index = cursor++; return hooks[index] ||= { current: value }; },
    useMemo: make => make(), useCallback: callback => callback,
    useEffect(effect, deps) {
      const index = cursor++, before = hooks[index];
      if (!before || deps.some((value, i) => !Object.is(value, before.deps[i]))) effects.push(() => {
        before?.cleanup?.(); hooks[index] = { deps, cleanup: effect() };
      });
    },
  };
  const send = async (path, method, body) => {
    sends.push([path, method, plain(body ?? null)]);
    if (path === model.CONNECTIONS_PATH && method === "POST") {
      record = { ...plain(body), id: "g1", name: "GitHub · acme", revision: 1, status: "CHECKED", plans: {}, children: [],
        credential: { roles: ["credential"], reference: false },
        checks: { checked_at: "2026-10-02T02:00:00Z", requested_at: "2026-10-02T01:00:00Z", job_id: null, stale: false, error: null,
          results: { identity: { status: "PASSED", items: ["admin_org", "read_enterprise"].map(permission => ({ permission, status: "GRANTED" })) } } } };
    } else if (path === `${model.CONNECTIONS_PATH}/g1/activate` && method === "POST") {
      record = { ...record, status: "ACTIVE", plans: plain(body.purposes) };
    } else if (path === `${model.CONNECTIONS_PATH}/g1/plans/identity` && method === "PUT") {
      record = { ...record, revision: record.revision + 1, plans: { identity: plain(body.plan) } };
    } else {
      assert.equal(`${method} ${path}`, `POST ${model.CONNECTIONS_PATH}/g1/check`, "unexpected fake request");
      record = { ...record, checks: { ...record.checks, checked_at: new Date().toISOString(), requested_plans: plain(body.plans) } };
    }
    return record;
  };
  const { ConnectWizard } = load("@/console/views/integrations/wizard.tsx", {
    globals: { window: { setTimeout: callback => timers.push(callback), clearTimeout() {} } },
    overrides: { react,
      "@/console/data": { ...load("@/console/data.ts"), useApi: () => ({ reload() {} }), useSaved: () => () => {}, send },
      "@/console/layer": { ...load("@/console/layer.tsx"), useToast: () => () => {} },
      "@/console/text": { ...load("@/console/text.ts"), useL: () => L },
      "@/components/locale": { ...load("@/components/locale.tsx"), useLocale: () => "ko" },
      "@/lib/dashboard-api": { api: async path => { assert.equal(path, `${model.CONNECTIONS_PATH}/g1`); return record; } },
    },
  });
  const elements = (node, match) => !node || typeof node !== "object" ? []
    : [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap(child => elements(child, match))];
  const text = node => typeof node === "string" ? node : !node || typeof node !== "object" ? ""
    : React.Children.toArray(node.props?.children).map(text).join("");
  const draw = () => {
    cursor = 0; effects = [];
    const catalog = { providers: [descriptor], purposes: ["identity"] };
    const entry = ConnectWizard({ catalog,
      open: existing ? { id: existing.id, step: 1 }
        : { provider: "github", purpose: "identity", edition: "cloud", target: { organization: "acme", enterprise: "acme-ent" } },
      admin: true, onClose() {}, go() {}, can: () => true });
    // Exercise the retained settings flow with its complete descriptor. The
    // public product gate is covered with real React in console-edition-entry.
    const shell = entry.type({ ...entry.props, catalog });
    const tree = shell.type(shell.props);
    effects.forEach(effect => effect());
    return tree;
  };
  const grid = name => elements(draw(), node => node.props.fields?.some(field => field.name === name) && node.props.values)[0];
  return { sends, grid,
    async ready() { draw(); await new Promise(resolve => setImmediate(resolve)); },
    async poll() { draw(); assert.equal(timers.length, 1); await timers.shift()(); },
    edition(value) { elements(draw(), node => node.props.label === "제품")[0].props.onChange(value); },
    change(name, value) { grid(name).props.onChange(name, value); },
    permissions: () => elements(draw(), node => node.props.className === "ig-perms").map(text).join(","),
    async click(label) {
      const button = elements(draw(), node => node.type === "button" && text(node) === label)[0];
      assert.ok(button, label); assert.ok(!button.props.disabled, `${label} is enabled`);
      button.props.onClick(); await new Promise(resolve => setImmediate(resolve));
    },
    async completeCheck() {
      await this.click("연결 확인"); draw();
      assert.equal(timers.length, 1); await timers.shift()();
      await this.click("다음"); await this.click("연동하고 수집 시작");
    },
  };
}

test("the wizard drops a stale enterprise choice from the checklist and activation after the target changes", async () => {
  const wizard = mountWizard();
  wizard.edition("enterprise_cloud");
  wizard.change("enterprise_identities", true);
  await wizard.click("다음");
  assert.equal(wizard.permissions(), "read:enterprise");
  await wizard.click("이전");
  wizard.change("enterprise", "");
  await wizard.click("다음");
  assert.equal(wizard.permissions(), "read:org");
  await wizard.completeCheck();
  assert.deepEqual(wizard.sends.at(-1), ["provider-connections/g1/activate", "POST", { purposes: { identity: {} } }]);
});

test("the wizard resets a chosen plan to the new edition's default before checking and activating", async () => {
  const wizard = mountWizard();
  wizard.edition("enterprise_cloud");
  wizard.change("enterprise_identities", true);
  wizard.change("enterprise_identities", false);
  assert.equal(wizard.grid("enterprise_identities").props.values.enterprise_identities, false);
  wizard.edition("dedicated");
  assert.equal(wizard.grid("enterprise_identities").props.values.enterprise_identities, true);
  await wizard.click("다음");
  assert.equal(wizard.permissions(), "read:enterprise");
  await wizard.completeCheck();
  assert.deepEqual(wizard.sends.at(-1), ["provider-connections/g1/activate", "POST", { purposes: { identity: { enterprise_identities: true } } }]);
});

test("a legacy GHE.com organization's active plan changes to enterprise without changing its schedule", async t => {
  const descriptor = { ...GH, purposes: { identity: { ...GH.purposes.identity, plan: [
    ...GH.purposes.identity.plan,
    { name: "schedule_minutes", label: "Schedule", label_ko: "수집 주기", kind: "number", default: 1440 },
  ] } } };
  for (const minutes of [1440, 60]) await t.test(`${minutes} minutes`, async () => {
    const wizard = mountWizard({ id: "g1", provider: "github", edition: "dedicated", name: "GitHub · acme", status: "ACTIVE", revision: 2,
      purposes: ["identity"], plans: { identity: { schedule_minutes: minutes } }, auth_method: "token",
      target: { organization: "acme", enterprise: "acme-ent" }, credential: { roles: ["credential"], reference: false },
      children: [{ kind: "idp", id: "i1", purpose: "identity" }],
      checks: { checked_at: "2026-10-02T02:00:00Z", requested_at: "2026-10-02T01:00:00Z", job_id: null, stale: false, error: null,
        results: { identity: { status: "PASSED", items: ["admin_org", "read_enterprise"].map(permission => ({ permission, status: "GRANTED" })) } } },
    }, descriptor);
    await wizard.ready();
    const shownAtStart = wizard.grid("enterprise_identities").props.values.enterprise_identities;
    wizard.change("enterprise_identities", false);
    wizard.change("enterprise_identities", true);
    await wizard.click("다음");
    assert.equal(wizard.permissions(), "read:enterprise");
    await wizard.click("권한 다시 확인");
    await wizard.poll();
    await wizard.click("다음");
    await wizard.click("변경 저장");
    assert.equal(wizard.sends[0][0], "provider-connections/g1/check");
    assert.deepEqual(wizard.sends.slice(1), [["provider-connections/g1/plans/identity", "PUT",
      { plan: { enterprise_identities: true, schedule_minutes: minutes }, expected_revision: 2 }]]);
    assert.equal(shownAtStart, false, "the saved legacy source still reads the organization");
  });
});

test("the manifest keeps what the API wrote and adds this CreMore's address", () => {
  const written = { name: "CreMore acme", public: false, default_permissions: { contents: "read" }, default_events: [] };
  const manifest = plain(app.manifestFor(written, "https://cremore.example.com"));
  assert.deepEqual(manifest, { ...written, url: "https://cremore.example.com", redirect_url: "https://cremore.example.com/github/app",
    setup_url: "https://cremore.example.com/github/app", hook_attributes: { url: "https://cremore.example.com/github/app", active: false } });
});

test("the manifest goes only to an organization's new App page on the GitHub the connection names", () => {
  assert.equal(app.trustedForm("https://github.com/organizations/acme/settings/apps/new?state=s.x"), true);
  assert.equal(app.trustedForm("https://github.example.com/organizations/acme/settings/apps/new?state=s", "https://github.example.com"), true);
  for (const [url, host] of [["https://evil.example/organizations/acme/settings/apps/new"], ["http://github.com/organizations/acme/settings/apps/new"],
    ["https://github.com/settings/apps/new"], ["https://github.com:8443/organizations/acme/settings/apps/new"],
    ["https://github.com/organizations/acme/settings/apps/new", "github.example.com"], ["not a url"]]) {
    assert.equal(app.trustedForm(url, host), false, url);
  }
});

test("typed GitHub hosts use the server's HTTPS normalization before trusting the manifest", () => {
  for (const host of ["https://api.acme.ghe.com", "HTTPS://API.Acme.GHE.COM:443/", " acme.ghe.com "]) {
    assert.equal(app.trustedForm("https://acme.ghe.com/organizations/acme/settings/apps/new", host), true, host);
  }
  assert.equal(app.trustedForm("https://ghes.acme.test/organizations/acme/settings/apps/new", "HTTPS://GHES.acme.test:443/"), true);
  assert.equal(app.trustedForm("https://github.com/organizations/acme/settings/apps/new", "api.github.com"), true);
  for (const host of ["http://acme.ghe.com", "https://acme.ghe.com:444", "https://u:p@acme.ghe.com", "https://acme.ghe.com/path",
    "https://acme.ghe.com/?query=1", "https://acme.ghe.com/#fragment"]) {
    assert.equal(app.trustedForm("https://acme.ghe.com/organizations/acme/settings/apps/new", host), false, host);
  }
  assert.equal(app.trustedForm("https://u:p@acme.ghe.com/organizations/acme/settings/apps/new", "acme.ghe.com"), false);
});

test("reachable GitHub refusals have Korean and English onboarding messages", () => {
  for (const code of ["GITHUB_HOST_INVALID", "GITHUB_ORGANIZATIONS_HTTP_401", "GITHUB_ORGANIZATIONS_HTTP_404",
    "GITHUB_ORGANIZATIONS_REQUEST_FAILED", "GITHUB_ORGANIZATIONS_INVALID", "GITHUB_ORGANIZATIONS_LIMIT",
    "GITHUB_APP_IDENTITY_MISMATCH", "GITHUB_APP_ID_INVALID", "WRITE_REQUIRED", "GITHUB_TOKEN_INVALID",
    "GITHUB_ENTERPRISE_SEALED_CREDENTIAL_REQUIRED"]) {
    const ko = model.detailText(code, L), en = model.detailText(code, (_ko, en) => en);
    assert.notEqual(ko, code); assert.notEqual(en, code); assert.notEqual(ko, en);
    assert.equal(model.onboardingText(code, [], L), ko);
  }
});

const elements = (node, match) => !node || typeof node !== "object" ? []
  : [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap(child => elements(child, match))];
const textOf = node => typeof node === "string" ? node : !node || typeof node !== "object" ? ""
  : React.Children.toArray(node.props?.children).map(textOf).join("");

test("GitHub discovery's existing setup path opens the selected PAT edition", async () => {
  const advanced = [];
  const { AuthFirstWizard } = load("@/console/views/integrations/auth-first.tsx", { overrides: {
    react: { ...React, useState: value => [typeof value === "function" ? value() : value, () => {}], useRef: value => ({ current: value }), useEffect() {} },
    "@/console/data": { useApi: () => ({}), useSaved: () => () => {} },
    "@/console/layer": { ...load("@/console/layer.tsx"), useToast: () => () => {} },
    "@/console/text": { ...load("@/console/text.ts"), useL: () => L },
    "@/components/locale": { useLocale: () => "ko" },
    "@/components/display-timezone": { useDisplayTimezone: () => "UTC" },
  } });
  const descriptor = { ...GH, auth_methods: GH.auth_methods.map(m => ({ ...m, auth_first: { context: ["host"] } })) };
  const tree = AuthFirstWizard({ descriptor, initialEdition: "dedicated", admin: true, onClose() {},
    onAdvanced: (...args) => advanced.push(args) });
  const link = elements(tree, node => node.type === "button" && textOf(node) === "다른 인증·기존 설정")[0];
  assert.ok(link, "GitHub offers the documented fallback instead of a dead end");
  link.props.onClick(); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(advanced, [["token", "dedicated"]]);
  // The retained settings flow accepts a named organization and enterprise (covered through activation above).
});

test("a GitHub App draft resumes its saved edition and card without a second product choice", () => {
  for (const product of ["enterprise_cloud", "dedicated", "enterprise_server"]) for (const entry of ["account", "exposure"]) {
    const stored = new Map([
      ["cremore:onboarding-entry:github", JSON.stringify({ edition: product, entry })],
      ["cremore:onboarding:github:new", JSON.stringify({ id: "draft", key: "x".repeat(43) })],
    ]);
    const globals = { sessionStorage: { getItem: key => stored.get(key) ?? null } };
    const auth = load("@/console/views/integrations/auth-first.tsx", { globals });
    const { ConnectWizard } = load("@/console/views/integrations/wizard.tsx", { globals, overrides: {
      react: { ...React, useState: value => [typeof value === "function" ? value() : value, () => {}], useMemo: make => make(), useEffect() {} },
      "@/console/text": { ...load("@/console/text.ts"), useL: () => L },
      "@/console/views/integrations/auth-first": auth,
    } });
    const descriptor = { ...GH, editions: [...GH.editions, edition("enterprise_server")], purposes: { ...GH.purposes, exposure: {} },
      auth_methods: GH.auth_methods.map(m => ({ ...m, purposes: ["identity", "exposure"] })) };
    const render = requestedEntry => ConnectWizard({ catalog: { providers: [descriptor], purposes: ["identity", "exposure"] },
      open: { provider: "github", entry: requestedEntry }, admin: true, onClose() {}, go() {}, can: () => true });
    const resumed = render(entry);
    assert.notEqual(resumed.props.labelledBy, "product-title");
    assert.equal(resumed.props.open.edition, product);
    assert.equal(resumed.props.open.entry, entry);
    assert.deepEqual(plain(resumed.props.catalog.providers[0].editions.map(e => e.id)), [product]);
    assert.equal(render(entry === "account" ? "exposure" : "account").props.labelledBy, "product-title", "another card never borrows the draft");
    stored.delete("cremore:onboarding:github:new");
    assert.equal(render(entry).props.labelledBy, "product-title", "a stale saved choice alone is not a returning App");
  }
});

test("each refusal on the way back reads as what to do", () => {
  assert.match(app.appErrorText("GITHUB_APP_NOT_INSTALLED", L), /설치를 마친 뒤 다시 확인/);
  assert.match(app.appErrorText("GITHUB_MANIFEST_CODE_EXPIRED", L), /1시간/);
  assert.match(app.appErrorText("SOMETHING_NEW", L), /SOMETHING_NEW/);
});

// startGitHubApp with a scripted API, browser store and page: what was asked of the API and whether the page left.
function starter({ storage = "ok", formUrl = "https://github.com/organizations/acme/settings/apps/new?state=s.x", cancel = "ok", entry } = {}) {
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  const calls = [], stored = new Map(), submitted = [];
  const sessionStorage = {
    setItem(key, value) { if (storage === "throws") throw Error("QuotaExceededError"); if (storage === "ok") stored.set(key, value); },
    getItem: key => stored.get(key) ?? null, removeItem: key => stored.delete(key),
  };
  const element = () => ({ append() {}, submit() { submitted.push(this.action); } });
  const module = load("@/console/views/integrations/github-app.tsx", {
    globals: { sessionStorage, window: { location: { origin: "https://cremore.example.com" } }, document: { createElement: element, body: { append() {} } } },
    overrides: { "@/lib/dashboard-api": { DashboardAPIError, api: async (path, init) => {
      calls.push([path, JSON.parse(init.body), init.keepalive]);
      if (path.endsWith("/cancel") && cancel === "fails") throw new DashboardAPIError("GITHUB_APP_SESSION_EXPIRED", 404);
      if (path.endsWith("/cancel") && cancel === "hangs") return new Promise(() => {});
      return path.endsWith("/start") ? { session_id: "s1", state: "s.x", expires_at: "2099-01-01T00:00:00Z", form_url: formUrl, manifest: { name: "CreMore acme" } } : {};
    } } },
  });
  const start = () => module.startGitHubApp({ edition: "cloud", target: { organization: "acme" }, onboarding: true, ...(entry === undefined ? {} : { entry }) });
  return { start, calls, stored, submitted, DashboardAPIError };
}

test("the page leaves for GitHub only once this tab holds the flow it must come back with", async () => {
  const ok = starter();
  await ok.start();
  assert.equal(ok.submitted.length, 1);
  const held = JSON.parse(ok.stored.get(app.GITHUB_APP_STORAGE));
  assert.equal(held.session_id, "s1"); assert.equal(held.state, "s.x"); assert.equal(held.browser_key, ok.calls[0][1].browser_key); assert.equal(held.onboarding, true);
  for (const storage of ["throws", "drops"]) {  // blocked outright, or a write that does not read back
    const blocked = starter({ storage });
    await assert.rejects(blocked.start(), error => error instanceof blocked.DashboardAPIError && error.message === "GITHUB_APP_STORAGE_UNAVAILABLE" && error.status === 409, storage);
    assert.deepEqual(blocked.submitted, [], `${storage}: no navigation`);
    assert.deepEqual(blocked.calls.map(([path]) => path), ["github/app-manifest/start", "github/app-manifest/cancel"]);
  }
});

test("the card the flow began from comes back with it, and only as one of the two cards", async () => {
  for (const [entry, kept] of [["exposure", "exposure"], ["account", "account"], ["admin", undefined], [undefined, undefined]]) {
    const s = starter({ entry });
    await s.start();
    assert.equal(JSON.parse(s.stored.get(app.GITHUB_APP_STORAGE)).entry, kept, String(entry));
    assert.equal("entry" in s.calls[0][1], false, "the API is not told the console card");
  }
});

// A cancel that never settles fails this test at its timeout instead of hanging the run.
test("a page that is not GitHub's own drops the flow on the server and stays here", { timeout: 5000 }, async () => {
  for (const cancel of ["ok", "fails", "hangs"]) {  // the cancel is told, not waited for
    const s = starter({ formUrl: "https://evil.example/organizations/acme/settings/apps/new", cancel });
    await assert.rejects(s.start(), error => error instanceof s.DashboardAPIError && error.message === "GITHUB_APP_RESPONSE_INVALID" && error.status === 502, cancel);
    assert.deepEqual(plain(s.calls.slice(1)), [["github/app-manifest/cancel", { session_id: "s1", browser_key: s.calls[0][1].browser_key }, true]]);
    assert.deepEqual(s.submitted, []);
    assert.equal(s.stored.size, 0, "no pending flow is kept for a page never visited");
  }
});

test("a sign-in page instead of the API's answer reads as a sign-in that ran out", () => {
  const { DashboardAPIError } = load("@/lib/dashboard-api.ts");
  assert.equal(app.codeOf(new DashboardAPIError("Invalid server response", 403)), "GITHUB_APP_SIGN_IN_EXPIRED");  // HTML body
  assert.equal(app.codeOf(new DashboardAPIError("GITHUB_APP_SIGN_IN_EXPIRED", 401)), "GITHUB_APP_SIGN_IN_EXPIRED");  // HTML 200, see post()
  assert.equal(app.codeOf(new DashboardAPIError("UNAUTHENTICATED", 401)), "GITHUB_APP_SIGN_IN_EXPIRED");
  assert.equal(app.codeOf(new DashboardAPIError("Invalid server response", 502)), "GITHUB_APP_UNAVAILABLE");  // a gateway page is not a sign-in
  assert.equal(app.codeOf(new DashboardAPIError("GITHUB_APP_STATE_INVALID: no", 409)), "GITHUB_APP_STATE_INVALID");
});

test("every refusal the GitHub App flow raises has words in both languages", () => {
  const en = (ko, english) => english;
  for (const code of ["GITHUB_APP_STORAGE_UNAVAILABLE", "GITHUB_APP_RESPONSE_INVALID", "GITHUB_APP_REQUEST_INVALID", "GITHUB_APP_BROWSER_KEY_INVALID",
    "GITHUB_ORGANIZATION_INVALID", "EDITION_UNKNOWN", "GITHUB_APP_SIGN_IN_EXPIRED"]) {
    assert.doesNotMatch(app.appErrorText(code, L), new RegExp(code), code);
    assert.doesNotMatch(app.appErrorText(code, en), new RegExp(code), code);
    assert.notEqual(app.appErrorText(code, L), app.appErrorText(code, en), code);
  }
});

test("the identity check and the enterprise refusal say what GitHub shows to whom", () => {
  assert.match(model.detailText("GITHUB_IDENTITY_SAML_NOT_ENABLED", L), /SAML 신원 공급자를 보여 주지 않음.*엔터프라이즈 소유자의 classic PAT/);
  assert.match(model.detailText("GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN", L), /엔터프라이즈 소유자의 classic PAT에만/);
});

test("people are read with the App only where GitHub shows an App an organization's SAML identities", () => {
  const app = { id: "github_app", label: "App", label_ko: "App", renewal: "AUTOMATIC", purposes: ["exposure", "identity"],
    purpose_editions: { identity: ["cloud", "enterprise_cloud"] } };
  const token = { id: "token", label: "PAT", label_ko: "PAT", renewal: "EXPIRES", purposes: ["exposure", "identity"] };
  const d = { ...GH, purposes: { ...GH.purposes, exposure: { permissions: [] } }, auth_methods: [app, token] };
  const ids = (purposes, edition) => model.methodsFor(d, purposes, edition).map(method => method.id);
  assert.deepEqual(ids(["identity"], "enterprise_cloud"), ["github_app", "token"]);
  assert.deepEqual(ids(["identity"], "dedicated"), ["token"]);  // GHE.com: managed users, an enterprise owner's token
  assert.deepEqual(ids(["exposure"], "dedicated"), ["github_app", "token"]);  // the narrowing is the identity purpose's
  // Signed in with the App on Server, people go to the token's group instead of riding along with the App.
  const { setupGroups } = load("@/console/views/integrations/setup.ts");
  const withInventory = { ...d, purposes: { ...d.purposes, inventory: { permissions: [] } },
    auth_methods: [{ ...app, purposes: ["exposure", "inventory", "identity"] }, token] };
  assert.deepEqual(plain(setupGroups(withInventory, ["inventory", "identity"], "enterprise_server", "github_app")), [
    { method: "github_app", edition: "enterprise_server", purposes: ["inventory"] },
    { method: "token", edition: "enterprise_server", purposes: ["identity"] }]);
  assert.deepEqual(plain(setupGroups(withInventory, ["inventory", "identity"], "enterprise_cloud", "github_app")), [
    { method: "github_app", edition: "enterprise_cloud", purposes: ["inventory", "identity"] }]);
});
