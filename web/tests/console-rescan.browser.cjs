// Synthetic proof of rescanning an exposed location from a credential's panel: an Analyst picks the location and an
// approved scan scope, prepares a plan (a refused preparation sends nothing further), then runs it with the plan's id
// and version; the run is reported as started, not as the value gone. A Viewer cannot start one and sends nothing.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { respond, refusal, openConsole, preview, capturedAt, settled, inBounds, assertClean, openMenu } = require("./console-proof.cjs");

const CREDENTIAL = "5db0c402-9087-42c0-9039-69bf34e32663", FINDING = "ee434166-6c89-4a00-84ea-516ad89b77df";
const EXPOSURE = "6dd89d2b-1169-4f97-b424-54230da1d306";
const UUID = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const CONNECTION = UUID(41), PROFILE = UUID(42), PLAN = UUID(43), JOB = UUID(44);

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const at = minutes => new Date(Date.parse(capturedAt()) + minutes * 60_000).toISOString();
  // The location was found through a registered integration, so it can be read again.
  const detail = answers[`findings/${FINDING}`];
  const finding = { ...detail, exposures: detail.exposures.map(item => ({ ...item, source_connection_ids: [CONNECTION] })) };
  // As the server gives them (cremore/api/routes/findings.py, cremore/scanning/scope.py profile_public and run_public).
  const profile = { kind: "source", connection_id: CONNECTION, id: PROFILE, name: "Backup bucket", version: 4, state: "READY", selected_roots: [], excluded_ids: [],
    budgets: { bytes: null, requests: null, seconds: null }, schedule_minutes: 0, event_mode: "OFF", change_reason: "backup review", catalog_snapshot_id: UUID(45),
    auth_revision: "auth-1", approved_by: "local operator", approved_at: at(-600) };
  const prepared = { kind: "source", connection_id: CONNECTION, plan_id: PLAN, profile_id: PROFILE, profile_version: 4, policy_digest: "a".repeat(64),
    expires_at: at(15), executable: true, known_count: 1, rescan_target: { finding_id: FINDING, exposure_id: EXPOSURE } };
  const run = { kind: "source", connection_id: CONNECTION, id: JOB, profile_id: PROFILE, profile_version: 4, scope_snapshot_id: PLAN, trigger: "RESCAN", mode: "BASELINE",
    status: "QUEUED", attempted: 0, succeeded: 0, failed: 0, skipped: 0, bytes: 0, requests: 0, engine_name: "NOT_RECORDED", engine_version: "NOT_RECORDED", created_at: at(1) };
  try {
    for (const role of ["Analyst", "Viewer"]) for (const theme of ["light", "dark"]) for (const width of [390, 1280]) {
      const label = `${role}-${theme}-${width}`;
      let previews = 0;
      const { context, page, record } = await openConsole(browser, { width, theme, view: "exposed", query: `&id=credential%3A${CREDENTIAL}`,
        answer: ({ method, endpoint }) => {
          if (endpoint === "session") return { ...answers.session, role };
          if (endpoint === `findings/${FINDING}`) return finding;
          if (endpoint === `findings/${FINDING}/rescan-profiles?exposure_id=${EXPOSURE}`) {
            return { finding_id: FINDING, exposure_id: EXPOSURE, kind: "source", connection_id: CONNECTION, profiles: [profile] };
          }
          if (method === "POST" && endpoint === `findings/${FINDING}/rescan-preview`) {
            // The first preparation is refused (the scope needs review meanwhile); the second gets a plan.
            return ++previews === 1 ? refusal(409, "NEEDS_SCOPE_REVIEW: the profile is not ready; review it first") : prepared;
          }
          if (method === "POST" && endpoint === `findings/${FINDING}/rescan`) return respond(202, run);
          return method === "GET" ? answers[endpoint] : undefined;
        } });
      try {
        await page.locator(".drawer").waitFor();
        await settled(page, record, label);
        await openMenu(page, page.locator(".drawer button[aria-label='작업']"));
        const item = page.locator(".menu .menu-item", { hasText: "노출 위치 다시 검사" });
        await item.waitFor();
        if (role === "Viewer") {
          assert.equal(await item.getAttribute("aria-disabled"), "true", `${label}: a Viewer cannot start a rescan`);
          await item.click({ force: true });
          assert.equal(await page.locator("[role=dialog]").count(), 0, `${label}: pressed anyway, nothing opens`);
          await page.keyboard.press("Escape");
          assert.deepEqual(record.writes, [], `${label}: a write`);
        } else {
          await item.click();
          const dialog = page.locator("[role=dialog]");
          await dialog.getByText("Backup bucket · v4").waitFor({ state: "attached" });
          await settled(page, record, label);
          await inBounds(page, `${label} rescan`);
          const prepare = dialog.locator("button", { hasText: "실행 계획 준비" });
          await prepare.click();
          await dialog.locator("[role=alert]").waitFor();
          assert.equal(record.writes.filter(write => write.endpoint === `findings/${FINDING}/rescan`).length, 0, `${label}: nothing runs after a refusal`);
          await prepare.click();
          await dialog.getByText(/실행 계획을 준비했습니다/).waitFor();
          await dialog.locator("button", { hasText: "다시 검사 실행" }).click();
          await dialog.waitFor({ state: "detached" });
          await page.getByText("다시 검사를 시작했습니다. 수집·탐지 현황에서 진행을 볼 수 있습니다.").waitFor();
          assert.deepEqual(record.writes.map(write => [write.endpoint, write.body]), [
            [`findings/${FINDING}/rescan-preview`, { exposure_id: EXPOSURE, profile_id: PROFILE, verify: false }],
            [`findings/${FINDING}/rescan-preview`, { exposure_id: EXPOSURE, profile_id: PROFILE, verify: false }],
            [`findings/${FINDING}/rescan`, { plan_id: PLAN, profile_version: 4, confirm: true }],
          ], `${label}: the requests`);
          // Started is not clean: the exposure still reads as found.
          assert.equal(await page.locator(".drawer").getByText("제거됨").count(), 0, `${label}: not reported as removed`);
        }
        assertClean(record, label);
      } finally { await context.close(); }
    }
    console.log("PASS console rescan: location and approved scope, a refused preparation runs nothing, the plan's id and version run it, reported as started; a Viewer cannot start one; light/dark at 390 and 1280.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
