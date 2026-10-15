// Synthetic proof of deleting an AWS key through its plans, in the credential's panel, in states the server can be in
// (one unfinished plan holds a key at a time). Requesting: the permanent-deletion acknowledgement comes before anything
// is sent; a send whose answer never came (lost, or the proxy not reaching the API) goes again with the same key, and a
// refused one starts over with a new key. One plan through its life: while it is unfinished no other can be requested;
// approving, executing and rechecking each send its content hash; executing waits for the installation's deletion
// switch and confirms in the danger style; an unknown outcome is only rechecked; Escape on a dialog above the panel
// closes the dialog only, also once the list behind has refreshed. A Viewer sees the plans and changes nothing.
// Korean and English, at 390 and 1440.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { LOST, respond, refusal, openConsole, preview, capturedAt, settled, inBounds, assertClean } = require("./console-proof.cjs");

const CREDENTIAL = "5db0c402-9087-42c0-9039-69bf34e32663";
const PLANS = `credentials/${CREDENTIAL}/action-plans`;
const ADMIN = "00000000-0000-0000-0000-000000000001", REQUESTER = "00000000-0000-4000-8000-0000000000a1", APPROVER = "00000000-0000-4000-8000-0000000000a2";
const UUID = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const DELETING = UUID(901), DISABLED = UUID(900), MADE = UUID(902);
const WORDS = {
  ko: { request: "조치 계획 요청", locked: "끝나지 않은 계획이 있습니다", approve: "승인", execute: "실행 요청", recheck: "상태 다시 확인", send: "계획 요청",
    off: "설치 설정에서 이 조치의 실행이 꺼져 있습니다.", ack: "같은 키를 되살릴 수 없는 영구 삭제임을 확인했습니다", needsAck: "영구 삭제 확인에 체크해야 합니다.",
    ids: ["조사 범위 근거 ID (변경관리 기록 UUID)", "복구 계획 근거 ID (변경관리 기록 UUID)", "사용처 ID (UUID)", "확인 담당자 ID (UUID)"] },
  en: { request: "Request a plan", locked: "An unfinished plan exists", approve: "Approve", execute: "Request execution", recheck: "Recheck the state", send: "Request the plan",
    off: "This installation has execution of this action turned off.", ack: "I acknowledge the same key cannot be restored after deletion", needsAck: "Acknowledge the permanent deletion.",
    ids: ["Scope evidence ID (change record UUID)", "Recovery evidence ID (change record UUID)", "Consumer ID (UUID)", "Owner ID (UUID)"] },
};

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const at = minutes => new Date(Date.parse(capturedAt()) + minutes * 60_000).toISOString();
  const base = { credential_id: CREDENTIAL, account_id: "000000000000", user_name: "test-user", principal_arn: "arn:aws:iam::000000000000:user/test-user",
    identifier_hint: "AWS masked A", requested_at: at(-60), reason_code: "EXPOSURE_CONTAINMENT",
    readiness: { confirmed_consumers: 1, declared_consumers: 1 } };
  const ready = { ...base.readiness, status: "READY_FOR_APPROVAL", reasons: [], execution_gate_passed: true };
  const plan = (id, hash, action, status, fields) => ({ ...base, id, action_type: action, status, requested_by: REQUESTER, plan_hash: String(hash).repeat(64),
    adapter_version: action === "DELETE_ACCESS_KEY" ? "AWS_DELETE_V1" : "AWS_DISABLE_V1", readiness: ready, expires_at: at(24 * 60), ...fields });
  // The key was disabled first: only an inactive key is deleted.
  const disabled = plan(DISABLED, 7, "DISABLE_ACCESS_KEY", "VERIFIED", { approved_by: APPROVER, approved_at: at(-120), provider_write_started_at: at(-110),
    executed_at: at(-110), verified_at: at(-110) });
  // What the server says of this key and installation: an unfinished plan holds the key, so no other is planned.
  const installation = { supported_actions: ["DISABLE_ACCESS_KEY", "DELETE_ACCESS_KEY"], rotation_execution_enabled: false };
  const policy = (plans, deletion) => {
    const locked = plans.some(item => ["PENDING_APPROVAL", "APPROVED", "QUEUED", "EXECUTING", "OUTCOME_UNKNOWN"].includes(item.status));
    return { ...installation, execution_enabled: true, independent_approval_required: true, single_operator: false, auth_mode: "oidc", owner_approval_required: false,
      deletion_execution_enabled: deletion, can_plan: !locked, can_delete: !locked,
      ...(locked ? { block_reason: "ACTION_PLAN_TARGET_LOCKED", deletion_block_reason: "ACTION_PLAN_TARGET_LOCKED" } : {}) };
  };
  const open = (role, locale, width, answer) => openConsole(browser, { width, locale, theme: "light", view: "exposed",
    query: `&id=credential%3A${CREDENTIAL}&dtab=remed`, answer: request => request.endpoint === "session" ? { ...answers.session, role } : answer(request) });
  const card = (page, hash) => page.locator(".plan-card").filter({ has: page.locator(`code:text("${String(hash).repeat(64)}")`) });
  try {
    for (const locale of ["ko", "en"]) for (const width of [390, 1440]) {
      const w = WORDS[locale];
      // One plan through its life, for an Admin and for a Viewer.
      for (const role of ["Admin", "Viewer"]) {
        const label = `${role}-${locale}-${width}`;
        let current = plan(DELETING, 9, "DELETE_ACCESS_KEY", "PENDING_APPROVAL", {}), deletion = false;
        const step = (status, fields) => { current = { ...current, status, ...fields }; return current; };
        const { context, page, record } = await open(role, locale, width, ({ method, endpoint }) => {
          const plans = [current, disabled];
          if (method === "GET" && endpoint === PLANS) return { plans, policy: policy(plans, deletion) };
          if (method === "POST" && endpoint === `action-plans/${DELETING}/approve`) return step("APPROVED", { approved_by: ADMIN, approved_at: at(1) });
          // The provider's answer is lost after the write started: the outcome is unknown, never run again.
          if (method === "POST" && endpoint === `action-plans/${DELETING}/execute`) {
            return step("OUTCOME_UNKNOWN", { provider_write_started_at: at(2), executed_at: at(2), safe_error_code: "AWS_RESPONSE_LOST" });
          }
          if (method === "POST" && endpoint === `action-plans/${DELETING}/recheck`) return step("VERIFIED", { verified_at: at(3), recheck_only: true, safe_error_code: null });
          return method === "GET" ? answers[endpoint] : undefined;
        });
        try {
          const deleting = card(page, 9);
          await deleting.waitFor();
          await settled(page, record, label);
          await inBounds(page, `${label} plans`);
          if (role === "Viewer") {
            for (const hash of [9, 7]) assert.equal(await card(page, hash).locator(".md-actions button:enabled").count(), 0, `${label} ${hash}: nothing to do`);
            assert.equal(await page.getByRole("button", { name: w.request }).count(), 0, `${label}: no plan to request`);
            assert.deepEqual(record.writes, [], `${label}: a write`);
          } else {
            // The unfinished plan holds the key: no other plan, and the reason on the button.
            const request = page.getByRole("button", { name: w.request });
            assert.equal(await request.isDisabled(), true, `${label}: another plan while one is unfinished`);
            assert.equal(await request.getAttribute("data-tip"), w.locked, `${label}: why`);
            // Escape on a dialog above the panel closes the dialog only, also once the list behind the panel has
            // refreshed (it reads again every minute).
            await deleting.getByRole("button", { name: w.approve, exact: true }).click();
            const dialog = page.locator("[role=dialog]");
            await dialog.waitFor();
            await page.clock.runFor(61_000);
            await settled(page, record, label);
            assert.ok(record.calls.filter(call => call.endpoint === "credential-records").length >= 2, `${label}: the list read again`);
            await page.keyboard.press("Escape");
            await dialog.waitFor({ state: "detached" });
            assert.equal(await page.locator(".drawer").count(), 1, `${label}: Escape on a dialog leaves the panel open`);
            // Approve: the content hash, after confirming.
            await deleting.getByRole("button", { name: w.approve, exact: true }).click();
            await page.locator("[role=dialog]").getByRole("button", { name: w.approve, exact: true }).click();
            await page.locator("[role=dialog]").waitFor({ state: "detached" });
            await settled(page, record, label);
            // With the deletion switch off, the approved plan does not run, and says why.
            const execute = deleting.getByRole("button", { name: w.execute, exact: true });
            assert.equal(await execute.isDisabled(), true, `${label}: deletion switch off`);
            await deleting.getByText(w.off).waitFor();
            // The installation turns deletion on: execute, confirmed in the danger style.
            deletion = true;
            await page.reload();
            await deleting.waitFor();
            await settled(page, record, label);
            await execute.click();
            const confirm = page.locator("[role=dialog]").getByRole("button", { name: w.execute, exact: true });
            assert.match(await confirm.getAttribute("class"), /danger-btn/, `${label}: an irreversible step is confirmed as one`);
            await confirm.click();
            await page.locator("[role=dialog]").waitFor({ state: "detached" });
            await settled(page, record, label);
            // An unknown outcome is only rechecked.
            assert.equal(await deleting.getByRole("button", { name: w.execute, exact: true }).count(), 0, `${label}: an unknown outcome does not run again`);
            await deleting.getByRole("button", { name: w.recheck, exact: true }).click();
            await settled(page, record, label);
            assert.deepEqual(record.writes.map(write => [write.method, write.endpoint, write.body]), [
              ["POST", `action-plans/${DELETING}/approve`, { plan_hash: "9".repeat(64) }],
              ["POST", `action-plans/${DELETING}/execute`, { plan_hash: "9".repeat(64) }],
              ["POST", `action-plans/${DELETING}/recheck`, { plan_hash: "9".repeat(64) }],
            ], `${label}: the content hash, each step once`);
            assert.equal(current.status, "VERIFIED", `${label}: rechecked`);
          }
          assertClean(record, label);
        } finally { await context.close(); }
      }
      // Requesting a deletion, for a key no unfinished plan holds.
      const label = `request-${locale}-${width}`;
      const sends = [];
      let made = null;
      const { context, page, record } = await open("Admin", locale, width, ({ method, endpoint, body }) => {
        const plans = made ? [made, disabled] : [disabled];
        if (method === "GET" && endpoint === PLANS) return { plans, policy: policy(plans, false) };
        if (method === "POST" && endpoint === PLANS) {
          sends.push(body.idempotency_key);
          // Refused (another request reserved the key at the same moment); lost on the way back; the proxy not reaching the
          // API; made.
          if (sends.length === 1) return refusal(409, "ACTION_PLAN_TARGET_LOCKED: another request reserved this target");
          if (sends.length === 2) return LOST;
          if (sends.length === 3) return respond(502, { error: "API is unavailable" });
          made = plan(MADE, 8, "DELETE_ACCESS_KEY", "PENDING_APPROVAL", { requested_by: ADMIN, operational_review: body.operational_review });
          return respond(201, made);
        }
        return method === "GET" ? answers[endpoint] : undefined;
      });
      try {
        await card(page, 7).waitFor();
        await settled(page, record, label);
        await page.getByRole("button", { name: w.request }).click();
        const form = page.locator("[role=dialog]");
        await form.locator("select").first().selectOption("DELETE_ACCESS_KEY");
        for (const [index, name] of w.ids.entries()) await form.getByLabel(name, { exact: true }).fill(UUID(index + 1));
        const send = form.locator("button", { hasText: w.send });
        assert.equal(await send.isDisabled(), true, `${label}: not without the acknowledgement`);
        await form.getByText(w.needsAck).waitFor();
        await form.getByText(w.ack).click();
        await inBounds(page, `${label} form`);
        for (let attempt = 1; attempt <= 3; attempt++) {
          await send.click();
          for (const deadline = Date.now() + 10_000; sends.length < attempt;) {
            assert.ok(Date.now() < deadline, `${label}: send ${attempt}`);
            await page.waitForTimeout(50);
          }
          await settled(page, record, `${label} send ${attempt}`);
          assert.equal(await form.isVisible(), true, `${label}: the form stays open after send ${attempt}`);
        }
        await send.click();
        await form.waitFor({ state: "detached" });
        await card(page, 8).waitFor();
        assert.equal(sends.length, 4, `${label}: four sends`);
        assert.notEqual(sends[1], sends[0], `${label}: a refused request starts over`);
        assert.deepEqual(sends.slice(2), [sends[1], sends[1]], `${label}: one key until an answer comes`);
        const last = record.writes.filter(write => write.endpoint === PLANS).at(-1).body;
        assert.equal(last.action_type, "DELETE_ACCESS_KEY", `${label}: the action`);
        assert.equal(last.operational_review.deletion_acknowledged, true, `${label}: acknowledged`);
        assert.deepEqual(record.writes.map(write => `${write.method} ${write.endpoint}`), Array(4).fill(`POST ${PLANS}`), `${label}: only the plan's sends`);
        // The new plan holds the key now.
        assert.equal(await page.getByRole("button", { name: w.request }).isDisabled(), true, `${label}: the key is held`);
        assertClean(record, label);
      } finally { await context.close(); }
    }
    console.log("PASS console key deletion: acknowledgement before a deletion is requested (an unanswered send goes again with the same key, a refused one with a new key), one unfinished plan holds the key, approve/execute/recheck send the content hash, execution waits for the deletion switch and confirms as irreversible, an unknown outcome is only rechecked; a Viewer changes nothing; ko/en at 390 and 1440.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
