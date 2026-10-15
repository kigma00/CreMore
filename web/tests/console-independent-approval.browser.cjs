// Real upload controls and plan dialogs; synthetic API only, no signing key or provider.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, capturedAt, respond, settled, inBounds, assertClean } = require("./console-proof.cjs");
const CREDENTIAL = "5db0c402-9087-42c0-9039-69bf34e32663", PLAN = "00000000-0000-4000-8000-000000000901";
const PATH = `credentials/${CREDENTIAL}/action-plans`, HASH = "a".repeat(64);
const words = {
  en: { execute: "Request execution", recheck: "Recheck the state", confirm: "Recheck", emergency: "Contain now", request: "Download approval request", file: "Signed approval file", error: "Do not upload a private key", reason: "Reason", cancel: "Cancel", attached: "Attached" },
  ko: { execute: "실행 요청", recheck: "상태 다시 확인", confirm: "다시 확인", emergency: "긴급 차단", request: "승인 요청 파일 받기", file: "서명 승인 파일", error: "개인키 파일은 올리지 마세요", reason: "사유", cancel: "취소", attached: "첨부됨" },
};

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    for (const [locale, theme, width] of [["en", "light", 1280], ["ko", "dark", 390]]) for (const mode of ["execute", "recheck", "emergency"]) {
      const w = words[locale], answers = preview(), label = `${mode}-${locale}-${width}`;
      const at = n => new Date(Date.parse(capturedAt()) + n * 60000).toISOString();
      let plan = { id: PLAN, credential_id: CREDENTIAL, account_id: "123456789012", user_name: "synthetic", principal_arn: "arn:aws:iam::123456789012:user/synthetic",
        identifier_hint: "AWS masked A", plan_hash: HASH, action_type: "DISABLE_ACCESS_KEY", status: mode === "recheck" ? "OUTCOME_UNKNOWN" : "APPROVED",
        reason_code: "EXPOSURE_CONTAINMENT", requested_by: "requester", approved_by: "approver", requested_at: at(-10), approved_at: at(-5), expires_at: at(60),
        readiness: { status: "READY_FOR_EXECUTION", reasons: [], execution_gate_passed: true },
        ...(mode === "recheck" ? { provider_write_started_at: at(-2) } : {}), ...(mode === "emergency" ? { emergency_eligible: true } : {}) };
      const proof = { claims: { version: 1, plan_id: PLAN, plan_hash: HASH, mode, expires_at: at(20), nonce: "synthetic" }, signature: "synthetic-signed-artifact" };
      const { context, page, record } = await openConsole(browser, { locale, theme, width, view: "exposed", query: `&id=credential%3A${CREDENTIAL}&dtab=remed`, answer: ({ endpoint, method, body }) => {
        if (method === "GET" && endpoint === PATH) return { plans: [plan], policy: { auth_mode: "oidc", execution_enabled: true, owner_approval_required: mode === "emergency", independent_authorization_required: true } };
        if (method === "GET" && endpoint === `action-plans/${PLAN}/authorization-request?mode=${mode}`) return { version: 1, plan: { id: PLAN, plan_hash: HASH }, mode };
        if (method === "POST" && endpoint === `action-plans/${PLAN}/${mode === "emergency" ? "emergency-execute" : mode}`) {
          assert.deepEqual(body.signed_approval, proof); assert.equal(body.plan_hash, HASH);
          plan = { ...plan, status: "QUEUED" }; return respond(202, plan);
        }
        return method === "GET" ? answers[endpoint] : undefined;
      } });
      try {
        const card = page.locator(".plan-card"); await card.waitFor(); await settled(page, record, label);
        await card.getByRole("button", { name: w[mode], exact: true }).click();
        const dialog = page.locator("[role=dialog]"); await dialog.waitFor();
        const confirm = dialog.getByRole("button", { name: mode === "recheck" ? w.confirm : w[mode], exact: true });
        if (mode === "emergency") { await dialog.locator("textarea").fill("Synthetic public exposure requires containment."); await dialog.locator('input[type="checkbox"]').check(); }
        assert.equal(await confirm.isDisabled(), true, `${label}: no signed file`);
        const input = dialog.getByLabel(w.file, { exact: true });
        const upload = value => input.setInputFiles({ name: "approval.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(value)) });
        await upload({ ...proof, claims: { ...proof.claims, mode: "wrong-mode" } });
        await dialog.getByText(w.error, { exact: false }).waitFor(); assert.equal(await confirm.isDisabled(), true);
        const download = page.waitForEvent("download"); await dialog.getByRole("button", { name: w.request }).click();
        assert.equal((await download).suggestedFilename(), `cremore-authorization-${PLAN}-${mode}.json`);
        await upload(proof); await dialog.getByText(`${w.attached}: approval.json`, { exact: true }).waitFor();
        assert.equal(await confirm.isEnabled(), true); await inBounds(page, label);
        // Dismissing the form clears the attachment; a later request starts with no approval selected.
        await page.keyboard.press("Escape"); await dialog.waitFor({ state: "detached" });
        await card.getByRole("button", { name: w[mode], exact: true }).click(); await dialog.waitFor();
        assert.equal(await confirm.isDisabled(), true);
        if (mode === "emergency") { await dialog.locator("textarea").fill("Synthetic public exposure requires containment."); await dialog.locator('input[type="checkbox"]').check(); }
        await upload(proof); await dialog.getByText(`${w.attached}: approval.json`, { exact: true }).waitFor();
        await confirm.click(); await dialog.waitFor({ state: "detached" }); await settled(page, record, label);
        assert.equal(record.writes.length, 1, `${label}: signed request only once`);
        assertClean(record, label);
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  console.log("PASS independent approval: execute, emergency and recheck require correct local file and send it once; download, escape/reset, KO/EN, light/dark and narrow layout.");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
