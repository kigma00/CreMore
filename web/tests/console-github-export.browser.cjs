// Real wizard and provider descriptor, synthetic resumed authorization only.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, frames } = require("./console-proof.cjs");
const app = bundle({ React: "react", client: "react-dom/client", wizard: "@/console/views/integrations/auth-first.tsx", locale: "@/components/locale.tsx",
  status: "@/console/views/integrations/github-export.tsx", collect: "@/console/views/integrations/collect.tsx", reach: "@/console/views/integrations/reach.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const fixture = JSON.parse(execFileSync("python", ["-c", `import json
from cremore_github_provider.onboarding import DESCRIPTORS
from cremore.onboarding.service import _fields
d=DESCRIPTORS[0]
p=_fields(d['purposes']['inventory']['plan'], {'audit_events': True, 'enterprise_audit': True}, 'enterprise_cloud', target={'enterprise':'acme-corp'})
print(json.dumps({'descriptor':d,'plan':p}))`], { cwd: path.join(__dirname, "../.."), encoding: "utf8" }));

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    for (const [language, theme, width] of [["ko", "light", 360], ["en", "dark", 1280]]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      try {
        const errors = [], calls = [];
        await context.addInitScript(data => {
          window.__fixture = data;
          window.__frame = requestAnimationFrame.bind(window);
          sessionStorage.setItem("cremore:onboarding:github:new", JSON.stringify({ id: "draft", key: "a".repeat(43), startNow: false }));
        }, app.data);
        const draft = { id: "draft", revision: 4, expires_at: new Date(Date.now() + 3600000).toISOString(), state: "SELECTED",
          edition: "enterprise_cloud", auth_method: "github_app", context: {}, purposes: ["inventory"], plans: { inventory: fixture.plan },
          authentication: { status: "GRANTED" }, roots: [{ id: "root", label: "acme", target: { organization: "acme", enterprise: "acme-corp" } }],
          selected_targets: ["root"], selected_resources: [], resources: [], blockers: [],
          checks: { results: { inventory: { items: fixture.descriptor.purposes.inventory.permissions.map(p => ({ permission: p.id, status: "GRANTED" })) } } } };
        const html = `<html lang="${language}" data-theme="${theme}"><meta charset="utf-8"><style>${css}</style><body><div id="root"></div><script>${app.preamble}
          client.createRoot(document.getElementById('root')).render(React.createElement(locale.LocaleContext.Provider,{value:'${language}'},React.createElement(wizard.AuthFirstWizard,{
            descriptor:${JSON.stringify(fixture.descriptor)},admin:true,initialEdition:'enterprise_cloud',onClose(){},onAdvanced(){}})));</script></body></html>`;
        await context.route("**/*", route => {
          const request = route.request(), url = new URL(request.url());
          if (url.origin !== ORIGIN) { errors.push("Unexpected external request"); return route.abort(); }
          if (request.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
          if (request.resourceType() === "image") return route.fulfill({ contentType: "image/svg+xml", body: '<svg xmlns="http://www.w3.org/2000/svg"/>' });
          const endpoint = url.pathname.replace(/^\/api\/backend\//, ""), body = request.postDataJSON();
          calls.push({ endpoint, body });
          let result;
          if (endpoint === "onboarding-sessions/draft/read") result = draft;
          else if (endpoint === "settings/scan-triggers") result = { schedules: { enabled: true } };
          else if (endpoint === "onboarding-sessions/draft/complete") result = { id: "saved", provider: "github", plans: body.schedules,
            checks: { authentication_only: false }, children: [] };
          else { errors.push(endpoint); return route.abort(); }
          return route.fulfill({ contentType: "application/json", body: JSON.stringify(result) });
        });
        const page = await context.newPage();
        page.on("pageerror", error => errors.push(error.message));
        await page.goto(ORIGIN);
        const name = field => language === "ko" ? field.label_ko : field.label;
        for (const [fieldName, value] of [["enterprise_schedule_minutes", "10080"], ["audit_schedule_minutes", "5"]]) {
          const field = fixture.descriptor.purposes.inventory.plan.find(f => f.name === fieldName);
          const select = page.getByLabel(name(field), { exact: true });
          await select.waitFor();
          assert.equal(await select.evaluate(el => el.tagName), "SELECT", "known intervals require no typing");
          await select.selectOption(value);
        }
        const primary = page.getByRole("combobox").first();
        await primary.selectOption("15");
        await frames(page);
        assert.equal(await page.getByRole("combobox").count(), 3);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        assert.equal(calls.some(c => c.endpoint.endsWith("/inspect")), false, "cadence changes need no new permission check");
        await page.getByRole("button", { name: language === "ko" ? "연동 저장" : "Save integration", exact: true }).click();
        await page.locator("#auth-first-done").waitFor();
        assert.deepEqual(calls.find(c => c.endpoint.endsWith("/complete")).body.schedules, {
          inventory: { schedule_minutes: 15, enterprise_schedule_minutes: 10080, audit_schedule_minutes: 5 },
        });
        assert.deepEqual(errors, []);
      } finally { await context.close(); }
    }
    for (const [language, theme, width] of [["ko", "light", 360], ["en", "dark", 1280]]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      try {
        const errors = [], snapshotCalls = [];
        const state = { stage: "queued", as_of: "2026-10-05T01:00:00Z", next_create_at: "2026-10-06T01:00:00Z",
          creation_allowed: false, reuse_available: true, request_blocked_reason: null,
          export_id: "PRIVATE_HANDLE_MUST_NOT_RENDER", signed_url: "PRIVATE_URL_MUST_NOT_RENDER" };
        await context.addInitScript(data => { window.__fixture = data; window.__frame = requestAnimationFrame.bind(window); }, app.data);
        const children = ["inventory", "audit"].map(id => ({ id, kind: "metadata", purpose: "inventory" }));
        const html = `<html lang="${language}" data-theme="${theme}"><meta charset="utf-8"><style>${css}</style><body><div id="root"></div><script>${app.preamble}
          client.createRoot(document.getElementById('root')).render(React.createElement(locale.LocaleContext.Provider,{value:'${language}'},
            React.createElement(React.Fragment,null,
              React.createElement(status.GitHubCollections,{connections:${JSON.stringify(children)}}),
              React.createElement(reach.GitHubAuditSources,{sources:[{connection_id:'audit',inventory:false,audit:true,current_revision:false,run:{status:'PARTIAL',finished_at:'2026-10-05T02:00:00Z',reasons:[]}}]}),
              React.createElement(collect.CollectionProgress,{requests:[{key:'inventory',purpose:'inventory',name:'Enterprise',jobId:'job'}]}))));</script></body></html>`;
        await context.route("**/*", route => {
          const request = route.request(), url = new URL(request.url());
          if (url.origin !== ORIGIN) { errors.push("Unexpected external request"); return route.abort(); }
          if (request.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
          const endpoint = url.pathname.replace(/^\/api\/backend\//, "");
          let result;
          if (endpoint === "v2/coverage/connections") result = { items: [
            { id: "inventory", enabled: true, spec: { provider: "github", name: "Enterprise inventory", schedule_minutes: 1440 }, enterprise_export: state },
            { id: "audit", enabled: true, spec: { provider: "github", name: "Enterprise audit", schedule_minutes: 5 } },
            { id: "unrelated", enabled: true, spec: { provider: "github", name: "UNRELATED_MUST_NOT_RENDER", schedule_minutes: 30 } },
          ] };
          else if (endpoint === "scan-runs/job") result = { status: "RUNNING", enterprise_export: state,
            schedule: { enabled: true, minutes: 1440, next_due_at: state.next_create_at } };
          else if (endpoint === "v2/coverage/connections/inventory/github-export-rows") {
            snapshotCalls.push(Object.fromEntries(url.searchParams));
            const offset = Number(url.searchParams.get("offset") || 0);
            result = { run: { id: "snapshot-1", status: "PARTIAL", finished_at: "2026-10-05T02:00:00Z" },
              current_revision: offset === 0, total: 51, next_offset: offset === 0 ? 50 : null,
              items: [{ id: "row-" + offset, kind: offset ? "principal" : "credential", as_of: "2026-10-05T01:00:00Z",
                permissions: [{ name: "contents", actions: ["read"] }],
                metadata: { credential_type: offset ? "github_app_installation" : "federated_jti", owner: "snapshot-owner-" + offset,
                  display_name: "long-export-observation-".repeat(6) } }] };
          }
          else { errors.push(endpoint); return route.abort(); }
          return route.fulfill({ contentType: "application/json", body: JSON.stringify(result) });
        });
        const page = await context.newPage();
        page.on("pageerror", error => errors.push(error.message));
        await page.goto(ORIGIN);
        await page.getByText(language === "ko" ? "GitHub에서 준비 중" : "Preparing at GitHub", { exact: true }).first().waitFor();
        await page.getByText("snapshot-owner-0", { exact: true }).waitFor();
        assert.equal(await page.getByText(language === "ko" ? "데이터 기준 시각" : "Data as of", { exact: true }).count(), 3);
        assert.match(await page.locator("#root").innerText(), language === "ko" ? /기존 결과/ : /reuses the export/);
        for (const [stage, ko, en, reason] of [
          ["quota_wait", "생성 한도 대기", "Waiting for export allowance", "GITHUB_EXPORT_QUOTA_WAIT"],
          ["submission_unknown", "생성 요청 결과 미확인", "Submission outcome unknown", "GITHUB_EXPORT_SUBMISSION_UNKNOWN"],
          ["complete", "결과 수집 완료", "Export collected", null],
        ]) {
          Object.assign(state, { stage, request_blocked_reason: reason, reuse_available: stage === "complete" });
          if (stage === "complete") state.last_success_at = "2026-10-05T03:00:00Z";
          await page.evaluate(() => window.dispatchEvent(new Event("focus")));
          await page.getByText(language === "ko" ? ko : en, { exact: true }).first().waitFor();
        }
        await frames(page);
        await page.getByRole("button", { name: language === "ko" ? "다음" : "Next", exact: true }).click();
        await page.getByText("snapshot-owner-50", { exact: true }).waitFor();
        assert.equal(snapshotCalls.at(-1).run_id, "snapshot-1", "paging must keep the same collection");
        assert.equal(snapshotCalls.at(-1).offset, "50");
        assert.equal(await page.getByRole("button", { name: language === "ko" ? "다음" : "Next", exact: true }).isDisabled(), true);
        await page.getByRole("button", { name: language === "ko" ? "최근 수집 보기" : "View latest collection", exact: true }).click();
        await page.getByText("snapshot-owner-0", { exact: true }).waitFor();
        assert.equal(snapshotCalls.at(-1).run_id, undefined);
        const shown = await page.locator("#root").innerText();
        assert.match(shown, /Enterprise inventory/);
        assert.match(shown, /Enterprise audit/);
        assert.match(shown, language === "ko" ? /5분/ : /5 min/);
        assert.match(shown, language === "ko" ? /고유 자격증명 수에 더하지/ : /do not increase unique credential/);
        assert.match(shown, language === "ko" ? /설정 변경 전 근거/ : /earlier configuration/);
        assert.doesNotMatch(shown, /MUST_NOT_RENDER/);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        assert.deepEqual(errors, []);
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  console.log("PASS GitHub cadences and live Export status: real wizard, shared allowance, data age, scope, privacy, KO/EN, light/dark, 360px");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
