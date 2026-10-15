// Account/content separation on the integrations page, with the real console and bounded fake responses: which card
// says connected, the two connected-services sections with their feature badges, and how each card opens.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { ORIGIN, openConsole, preview, settled, inBounds, assertClean, openMenu, frames } = require("./console-proof.cjs");
const descriptors = JSON.parse(execFileSync("python", ["-c", "import json; from cremore.onboarding.catalog import public; print(json.dumps(public()))"], {
  cwd: path.join(__dirname, "../.."), encoding: "utf8", env: { ...process.env, AWS_EC2_METADATA_DISABLED: "true" },
}));
const notion = descriptors.find(d => d.provider === "notion"), awsDescriptor = descriptors.find(d => d.provider === "aws");
const checks = { checked_at: "2026-10-06T16:10:12Z", requested_at: null, job_id: null, stale: false, error: null, results: {} };
const card = (page, name) => page.locator(".ig-card").filter({ has: page.locator(".ig-card-name", { hasText: new RegExp(`^${name}$`) }) });
const texts = locator => locator.allTextContents().then(all => all.map(text => text.trim()));

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    for (const [locale, theme, width] of [["ko", "light", 1440], ["en", "dark", 360], ["ko", "dark", 768]]) {
      const word = (ko, en) => locale === "ko" ? ko : en;
      const label = `${locale} ${theme} ${width}`;
      // A Notion page-reading connection (content only) and an authentication-only owner made before content was chosen.
      const contentOnly = { id: "11111111-1111-4111-8111-111111111111", provider: "notion", edition: "standard", name: "Pages reader",
        auth_method: "integration", status: "ACTIVE", revision: 2, purposes: ["exposure"], plans: { exposure: {} }, feature_enabled: { exposure: true },
        target: {}, children: [], checks, credential: { roles: ["credential"] }, renewal: null };
      const owner = { id: "33333333-3333-4333-8333-333333333333", provider: "notion", edition: "standard", name: "Workspace owner",
        auth_method: "integration", status: "CHECKED", revision: 1, purposes: [], plans: {}, target: {}, children: [],
        checks: { ...checks, authentication_only: true }, credential: { roles: ["credential"] }, renewal: null };
      const base = preview();
      const env = await openConsole(browser, { locale, theme, width, view: "sources", answer: ({ endpoint, method }) => {
        if (endpoint === "provider-connections/capabilities") return { ...base[endpoint], sources: [] };
        if (endpoint === "provider-connections/catalog") return { providers: [notion], purposes: ["exposure", "inventory", "remediation"] };
        if (endpoint === "provider-connections") return [contentOnly, owner];
        if (endpoint === `provider-connections/${owner.id}`) return owner;
        if (endpoint === `provider-connections/${owner.id}/targets/draft`) return { id: "draft", provider: "notion", edition: "standard", auth_method: "integration",
          revision: 1, state: "WORKING", expires_at: "2099-01-01T00:00:00Z", context: {}, purposes: [], plans: {}, editing: owner.id, previous_plans: {} };
        if (endpoint === "onboarding-sessions/draft/read") return { id: "draft", provider: "notion", edition: "standard", auth_method: "integration",
          revision: 1, state: "WORKING", expires_at: "2099-01-01T00:00:00Z", context: {}, purposes: [], plans: {}, editing: owner.id, previous_plans: {} };
        return method === "GET" ? base[endpoint] : undefined;
      } });
      try {
        const { page, record } = env;
        await settled(page, record);
        // The account card is Enterprise's: it never says connected for a content scan, and names the plan its features need.
        const account = card(page, "Notion");
        assert.equal(await account.locator(".ig-badge.on").count(), 0, `${label}: a content-only connection leaves the account card unconnected`);
        assert.match(await account.locator(".ig-card-desc").innerText(), new RegExp(word("Enterprise 전용: 발급 목록·조치", "Enterprise only: Inventory · Actions")));
        assert.deepEqual(await texts(account.locator(".cap")), [word("발급 목록 2종", "Inventory · 2 types"), word("조치", "Actions")], `${label}: Enterprise's features only`);
        const content = card(page, `Notion · ${word("콘텐츠 검사", "Content scan")}`);
        assert.equal(await content.locator(".ig-badge.on").count(), 1, `${label}: the running scan connects the content card`);
        // Two sections: nothing under accounts, both connections under content, each feature with its state.
        const accounts = page.locator("#ig-conn"), scans = page.locator("#ig-conn-exposure");
        assert.equal(await accounts.getByRole("heading", { name: word("계정·발급 목록 연결", "Account and inventory connections") }).count(), 1);
        await accounts.getByText(word("연결한 계정·발급 목록이 없습니다", "No account or inventory is connected"), { exact: true }).waitFor();
        assert.equal(await scans.getByRole("heading", { name: word("콘텐츠 검사 위치 연결", "Content scan connections") }).count(), 1);
        assert.equal(await scans.locator(".ig-row:not(.head)").count(), 2);
        const scanRow = scans.locator(".ig-row").filter({ hasText: "Pages reader" });
        assert.deepEqual(await texts(scanRow.locator(".cap")), [word("노출 검사 · 켜짐", "Exposure scan · on")]);
        const ownerRow = scans.locator(".ig-row").filter({ hasText: "Workspace owner" });
        assert.equal(await ownerRow.locator(".cap").count(), 0);
        assert.match(await ownerRow.locator(".igs").innerText(), new RegExp(word("계정 인증만 완료", "Account sign-in only")));
        await inBounds(page, label);
        // Two owners: the content card asks which one.
        assert.equal(await content.getAttribute("aria-haspopup"), "menu");
        await openMenu(page, content);
        assert.equal(await page.getByRole("menuitem").count(), 2);
        await page.keyboard.press("Escape");
        await page.locator(".menu").waitFor({ state: "detached" });
        // The authentication-only owner goes on to choose locations with its saved sign-in: no new credential.
        await Promise.all([page.waitForResponse(r => r.url().endsWith("/targets/draft")),
          ownerRow.getByRole("button", { name: word("검사 위치 고르기", "Choose scan locations"), exact: true }).click()]);
        assert.equal(record.writes.filter(r => r.endpoint === "onboarding-sessions").length, 0, `${label}: the owner's credential is reused`);
        assertClean(record, label);
      } finally { await env.context.close(); }
    }

    // No connection yet: a content card with a sign-in-first method starts a content-only flow of its own.
    {
      const base = preview();
      const env = await openConsole(browser, { view: "sources", answer: ({ endpoint, method }) => {
        if (endpoint === "provider-connections/catalog") return { providers: [notion], purposes: ["exposure", "inventory", "remediation"] };
        if (endpoint === "provider-connections") return [];
        return method === "GET" ? base[endpoint] : undefined;
      } });
      try {
        const { page, record } = env;
        await settled(page, record);
        await page.locator("#ig-conn").getByText("연결한 계정·발급 목록이 없습니다", { exact: true }).waitFor();
        await page.locator("#ig-conn-exposure").getByText("연결한 콘텐츠 검사 위치가 없습니다", { exact: true }).waitFor();
        const content = card(page, "Notion · 콘텐츠 검사");
        assert.equal(await content.isEnabled(), true, "no account needed first");
        assert.equal(await content.getAttribute("aria-haspopup"), null);
        assert.match(await content.locator(".ig-card-cta").innerText(), /연동하기/);
        await content.click();
        await page.locator("#product-title").filter({ hasText: "제품 선택" }).waitFor();
        assert.equal(record.writes.length, 0, "product choice never sends credentials");
        // A connect link keeps its entry: content offers every plan that scans pages, the account side Enterprise only.
        await settled(page, record);
        await page.goto(`${ORIGIN}/?view=sources&connect=notion&entry=exposure`); await settled(page, record);
        await page.locator("#product-title").waitFor();
        assert.equal(await page.getByRole("dialog").locator("select option").count(), 2, "both plans scan pages");
        assert.equal(new URL(page.url()).searchParams.get("entry"), null);
        await settled(page, record);
        await page.goto(`${ORIGIN}/?view=sources&connect=notion&entry=account`); await settled(page, record);
        await page.locator("#auth-first-title").waitFor();
        assert.equal(await page.locator("#product-title").count(), 0, "the account side has one plan");
        assert.equal(record.writes.length, 0);
        assertClean(record);
      } finally { await env.context.close(); }
    }

    // AWS: S3 reads through the account's role, so its card waits for an account; one account opens directly. An
    // account with inventory and S3 scans is listed in both sections.
    const awsBase = preview();
    const awsConn = { id: "22222222-2222-4222-8222-222222222222", provider: "aws", edition: "cloud", name: "Amazon Web Services",
      status: "ACTIVE", revision: 3, purposes: ["inventory"], plans: { inventory: { schedule_minutes: 0 } }, feature_enabled: { inventory: false },
      target: { account_id: "123456789012" }, auth_method: "runtime", credential: { roles: [] }, children: [],
      checks: { checked_at: "2026-10-06T16:10:12Z", requested_at: null, stale: true, results: {} } };
    let awsList = [], awsHealth = [];
    const awsEnv = await openConsole(browser, { view: "sources", answer: ({ endpoint, method }) => {
      if (endpoint === "provider-connections/capabilities") return { ...awsBase[endpoint], sources: [] };
      if (endpoint === "provider-connections/catalog") return { providers: [awsDescriptor], purposes: ["exposure", "inventory", "vault"] };
      if (endpoint === "provider-connections") return awsList;
      if (endpoint === `provider-connections/${awsConn.id}`) return awsList[0];
      if (endpoint === "operations/connections") return { items: awsHealth };
      if (endpoint === "connections/aws/acct/scan-scope-profiles") return { state: "READY", profiles: [{ id: "buckets", version: 1, name: "Buckets",
        state: "APPROVED", selected_roots: [{ resource_id: "bucket-a" }], excluded_ids: [], approved_at: "2026-10-01T00:00:00Z" }] };
      if (method === "POST" && endpoint === "scan-scope-profiles/buckets/preview") return { plan_id: "plan-1", executable: true };
      if (method === "POST" && endpoint === "scan-runs") return { id: "run-1" };
      return method === "GET" ? awsBase[endpoint] : undefined;
    } });
    try {
      const { page, record } = awsEnv;
      await settled(page, record);
      const s3 = card(page, "Amazon S3"), accountCard = card(page, "Amazon Web Services");
      assert.equal(await s3.isDisabled(), true, "no AWS account yet");
      assert.match(await s3.locator(".ig-card-cta").innerText(), /먼저 계정을 연결하세요/);
      assertClean(record, "AWS without an account");
      awsList = [awsConn];
      await page.reload(); await settled(page, record);
      assert.match(await s3.locator(".ig-card-top img").getAttribute("src"), /\/logos\/s3\.svg$/, "the S3 card shows the S3 mark");
      assert.equal(await accountCard.locator(".ig-badge.on").count(), 0, "a switched-off inventory is not connected");
      assert.equal(await s3.getAttribute("aria-haspopup"), null, "one account opens directly");
      await s3.click();
      await page.locator("#ig-title").filter({ hasText: "Amazon S3" }).waitFor();
      assert.equal(await page.locator(".menu").count(), 0);
      assert.match(await page.locator("#ig-title img").getAttribute("src"), /\/logos\/s3\.svg$/);
      assert.equal(await page.locator(".ig-feat-card").count(), 0, "the S3 view asks for no feature choice");
      assert.equal(await page.getByRole("heading", { name: "노출을 검사할 위치", exact: true }).count(), 1, "the scan section is there");
      // The AWS reads are left unanswered here: which ones a view makes says which sections it mounted.
      assert.deepEqual(record.unknown, ["aws/scanner-identity"], "the S3 view mounts none of the account's AWS settings");
      await page.keyboard.press("Escape");
      await page.locator("#ig-title").waitFor({ state: "detached" });
      assert.match(await accountCard.locator(".ig-card-top img").getAttribute("src"), /\/logos\/aws\.png$/);
      await openMenu(page, accountCard);
      await page.getByRole("menuitem", { name: /Amazon Web Services/ }).first().click();
      await page.locator("#ig-title").filter({ hasText: "Amazon Web Services" }).waitFor();
      assert.equal(await page.locator(".ig-feat-card").filter({ hasText: "평문 노출 검사" }).count(), 0, "the account card leaves the scan to the S3 card");
      assert.equal(await page.locator("#ig-scope").count(), 0);
      assert.ok(record.unknown.includes("settings/aws-credential-inventory"), "the account card keeps the account's AWS settings");
      await page.keyboard.press("Escape");
      await page.locator("#ig-title").waitFor({ state: "detached" });
      // A link's entry (a provider's return page sends one) opens the same side; anything else is dropped.
      for (const [entry, title] of [["exposure", "Amazon S3"], ["bogus", "Amazon Web Services"]]) {
        await settled(page, record);
        await page.goto(`${ORIGIN}/?view=sources&edit=${awsConn.id}&entry=${entry}`); await settled(page, record);
        await page.locator("#ig-title").filter({ hasText: title }).waitFor();
        assert.equal(new URL(page.url()).searchParams.get("entry"), null, `${entry}: the link's entry is consumed`);
        await page.keyboard.press("Escape");
        await page.locator("#ig-title").waitFor({ state: "detached" });
      }
      record.unknown.length = 0;

      // Inventory and S3 scans on, a vault comparison held back for a missing permission: both cards connected, a
      // row in each section with its own badges and menu. The S3 scans read through the account record the
      // inventory made (purpose inventory, as AWS onboarding records it).
      awsList = [{ ...awsConn, purposes: ["inventory", "exposure", "vault"], plans: { inventory: { schedule_minutes: 0 }, exposure: {} },
        feature_enabled: { inventory: true, exposure: true }, children: [{ kind: "aws_account", id: "acct", purpose: "inventory", account_id: "123456789012" }],
        checks: { ...checks, results: { vault: { status: "MISSING", items: [{ permission: "secrets_list", status: "MISSING" }] } } } }];
      awsHealth = [{ key: "aws_account:acct", kind: "aws_account", id: "acct", provider: "aws", name: "123456789012", auth_state: "READY", auth_reason: null,
        expires_at: null, expiry_stage: "NONE", last_success_at: "2026-10-05T00:00:00Z", last_failure_at: null, last_failure_code: null, last_status: "COMPLETE", freshness: "FRESH" }];
      await page.reload(); await settled(page, record);
      assert.equal(await accountCard.locator(".ig-badge.on").count(), 1);
      assert.equal(await s3.locator(".ig-badge.on").count(), 1);
      const accountRow = page.locator("#ig-conn .ig-row:not(.head)"), scanRow = page.locator("#ig-conn-exposure .ig-row:not(.head)");
      assert.equal(await accountRow.count(), 1); assert.equal(await scanRow.count(), 1);
      assert.deepEqual(await accountRow.locator(".cap").evaluateAll(all => all.map(el => el.dataset.state)), ["on", "missing"]);
      assert.match((await texts(accountRow.locator(".cap")))[1], /Secret 대조 · 권한 부족/);
      const held = accountRow.locator(".cap[data-state=missing]");
      assert.match(await held.getAttribute("data-tip"), /없는 권한: Secrets Manager 시크릿 목록/);
      // The missing permission is in the badge's own text for a screen reader, and the badge takes focus for its tooltip.
      assert.match(await held.locator(".sr").textContent(), /없는 권한: Secrets Manager 시크릿 목록/);
      await held.focus();
      assert.equal(await held.evaluate(el => el === document.activeElement), true);
      assert.match(await accountRow.locator(".igs").innerText(), /일부 기능 권한 부족/);
      assert.deepEqual(await texts(scanRow.locator(".cap")), ["노출 검사 1곳 · 켜짐"], "the scoped bucket count");
      assert.notEqual((await scanRow.locator(".ig-last").innerText()).trim().split("\n").pop(), "—", "the account's scan run is the content row's last run");
      const menuItems = async row => {
        await openMenu(page, row.locator(".ig-more button"));
        const names = await texts(page.locator(".menu .menu-item"));
        await page.keyboard.press("Escape");
        await page.locator(".menu").waitFor({ state: "detached" });
        await frames(page);
        return names;
      };
      assert.equal((await menuItems(accountRow)).includes("검사 대상 설정"), false, "scan targets are the content row's");
      assert.equal((await menuItems(scanRow)).includes("검사 대상 설정"), true);
      // S3's Collect now runs the scan scope through the shared account, and nothing of the inventory.
      const before = record.writes.length;
      await openMenu(page, scanRow.locator(".ig-more button"));
      const collect = page.locator(".menu .menu-item", { hasText: "지금 수집" });
      assert.equal(await collect.getAttribute("aria-disabled"), null, "S3 Collect now is enabled");
      await collect.click();
      await page.getByText("수집을 시작했습니다 (1건)").waitFor();
      assert.deepEqual(record.writes.slice(before).map(w => `${w.method} ${w.endpoint}`), ["POST scan-scope-profiles/buckets/preview", "POST scan-runs"]);
      await settled(page, record);
      await openMenu(page, scanRow.locator(".ig-more button"));
      await page.locator(".menu .menu-item", { hasText: "연동 해제" }).click();
      await page.getByRole("dialog").getByText("두 곳이 모두 멈춥니다", { exact: false }).waitFor();
      await inBounds(page, "AWS in both sections");
      await page.getByRole("dialog").getByRole("button", { name: "취소", exact: true }).click();
      assertClean(record, "AWS in both sections");
    } finally { await awsEnv.context.close(); }

    // An Enterprise workspace may still keep a page-reading account without Admin API access, from the account card.
    const base = preview();
    let enterpriseDraft;
    const enterprise = await openConsole(browser, { view: "sources", answer: ({ endpoint, method, body }) => {
      if (endpoint === "provider-connections/catalog") return { providers: [notion], purposes: ["exposure", "inventory", "remediation"] };
      if (endpoint === "provider-connections") return [];
      if (endpoint === "onboarding-sessions") {
        assert.equal(body.edition, "enterprise"); assert.equal(body.auth_method, "integration");
        enterpriseDraft = { id: "enterprise-draft", provider: "notion", edition: "enterprise", auth_method: "integration",
          revision: 1, state: "WORKING", expires_at: "2099-01-01T00:00:00Z", context: {}, purposes: [], plans: {} };
        return enterpriseDraft;
      }
      if (endpoint === "onboarding-sessions/enterprise-draft/read") return { ...enterpriseDraft, state: "AUTHENTICATED", authentication: { status: "GRANTED" } };
      return method === "GET" ? base[endpoint] : undefined;
    } });
    try {
      const { page, record } = enterprise;
      await settled(page, record);
      await card(page, "Notion").click();
      // Only Enterprise offers the account's features, so the product choice is skipped.
      await page.locator("#auth-first-title").waitFor();
      assert.equal(await page.locator("#product-title").count(), 0, "no product choice for a single account edition");
      assert.equal(await page.getByText(/조직 봇 토큰\(Enterprise\)|Organization bot token \(Enterprise\)/, { exact: true }).count(), 1);
      const integration = page.getByText(/내부 연결 토큰|Internal connection token/);
      assert.equal(await integration.count(), 1, "Enterprise also permits a page-reading account without Admin API access");
      assert.equal(record.writes.length, 0);
      await page.getByRole("combobox").filter({ has: integration }).selectOption("integration");
      await page.getByLabel(/^(토큰|Token)$/).fill("synthetic-enterprise-content-credential");
      await page.getByRole("button", { name: /^(인증 확인|Authenticate)$/ }).click();
      await page.getByRole("button", { name: /^(계정 연결 저장|Save account connection)$/ }).waitFor();
      assert.equal(await page.locator(".ig-feat-card").count(), 0, "page-only authentication never asks for Enterprise inventory permissions");
      assert.equal(record.writes.some(r => /discover|inspect|scan-runs|collect|scope/.test(r.endpoint)), false);
      assertClean(record);
    } finally { await enterprise.context.close(); }
  } finally { await browser.close(); }
  console.log("PASS account/content cards and sections: Notion content-only and authentication-only owners, a content-only start, AWS account-first S3 opened directly and listed in both sections, KO/EN, light/dark, 360/768/1440");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
