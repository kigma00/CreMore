// Synthetic proof of issuance and storage records on the Secret stores screen: an Admin links a collected issued
// credential and vault location to a source record; a response lost on the way back is sent again with the same id
// (one record, not two); revoking keeps the row; a Viewer gets the list and nothing to change. Light/dark, phone and
// desktop widths.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { LOST, respond, openConsole, preview, settled, inBounds, assertClean } = require("./console-proof.cjs");

const RECEIPTS = "coverage/storage-receipts";
const UUID = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const C_ISSUER = UUID(11), C_VAULT = UUID(12), RUN_ISSUER = UUID(21), RUN_VAULT = UUID(22), OLD = UUID(31);
const anchor = (run, item) => ({ run_id: run, batch_index: 0, item_index: item });
// Locators as the server gives them (cremore/coverage/storage_receipts.py _locator, schema 1).
const ISSUER = { anchor: anchor(RUN_ISSUER, 2), schema_version: 1, connection_id: C_ISSUER, connection_name: "GitLab · issued tokens", connection_revision: 1,
  provider: "gitlab", reference: "project/7/token/41", version: "", identifier: "deploy-bot", account_id: null, credential_type: "GITLAB_PAT", namespace: null, mount: null };
const VAULT = { anchor: anchor(RUN_VAULT, 5), schema_version: 1, connection_id: C_VAULT, connection_name: "Vault · kv", connection_revision: 1,
  provider: "vault", reference: "kv/data/deploy-bot", version: "3", identifier: null, account_id: null, credential_type: null, namespace: "admin", mount: "kv" };
const receipt = (id, fields) => ({ id, source_system: "vault-rotation", source_record_id: "rotation/2026-09-28/123", stored_at: "2026-09-28T03:00:00+00:00",
  submitted_at: "2026-09-28T04:00:00+00:00", submitted_by: "local operator", revoked_at: null, revoked_by: null, issuer: ISSUER, vault: VAULT,
  state: "STORAGE_RECORDED", applicable: true, reasons: [], ...fields });

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  try {
    for (const role of ["Admin", "Viewer"]) for (const theme of ["light", "dark"]) for (const width of [390, 1280]) {
      const label = `${role}-${theme}-${width}`;
      const list = [receipt(OLD, {})];
      let posts = 0;
      const { context, page, record } = await openConsole(browser, { width, theme, view: "vaults", answer: ({ method, endpoint, body }) => {
        if (endpoint === "session") return { ...answers.session, role };
        if (method === "GET" && endpoint.startsWith(`${RECEIPTS}?`)) return { items: list, total: list.length, offset: 0, limit: 20 };
        if (endpoint === `${RECEIPTS}/connections`) return { items: [
          { id: C_ISSUER, name: ISSUER.connection_name, provider: "gitlab", enabled: true, revision: 1 },
          { id: C_VAULT, name: VAULT.connection_name, provider: "vault", enabled: true, revision: 1 }] };
        if (endpoint.startsWith(`${RECEIPTS}/connections/`)) {
          const run = endpoint.includes(C_ISSUER) ? RUN_ISSUER : RUN_VAULT;
          return { items: [{ id: run, status: "COMPLETE", started_at: "2026-09-28T02:00:00+00:00", finished_at: "2026-09-28T02:05:00+00:00", revision: 1 }], total: 1, offset: 0, limit: 20 };
        }
        if (endpoint.startsWith(`${RECEIPTS}/observations?`)) return { items: [endpoint.includes("role=issuer") ? ISSUER : VAULT], total: 1, offset: 0, limit: 100 };
        if (method === "POST" && endpoint === RECEIPTS) {
          // The first answer is lost on the way back: the server kept the record, the page did not hear.
          if (++posts === 1) return LOST;
          list.unshift(receipt(body.id, { source_record_id: body.source_record_id, source_system: body.source_system, stored_at: body.stored_at }));
          return respond(201, list[0]);
        }
        if (method === "POST" && endpoint === `${RECEIPTS}/${OLD}/revoke`) {
          list[list.length - 1] = { ...list[list.length - 1], revoked_at: "2026-10-01T00:00:00+00:00", revoked_by: "local operator", state: "REVOKED",
            applicable: false, reasons: ["RECEIPT_REVOKED"] };
          return list[list.length - 1];
        }
        return method === "GET" ? answers[endpoint] : undefined;
      } });
      try {
        await settled(page, record, label);
        const card = page.locator(".card").filter({ has: page.locator("table") }).filter({ hasText: "vault-rotation" });
        await card.waitFor();
        await inBounds(page, `${label} list`);
        if (role === "Viewer") {
          assert.equal(await card.locator("button", { hasText: /이력 추가/ }).count(), 0, `${label}: nothing to add`);
          assert.equal(await card.locator("button[aria-label='저장 이력 철회']").count(), 0, `${label}: nothing to revoke`);
          assert.deepEqual(record.writes, [], `${label}: a write`);
        } else {
          await card.locator("button", { hasText: /이력 추가/ }).click();
          const dialog = page.locator("[role=dialog]");
          await dialog.waitFor();
          for (const [title, item] of [["발급 Credential", ISSUER], ["저장소 위치", VAULT]]) {
            await dialog.locator(`select[aria-label="${title} 연결"]`).selectOption(item.connection_id);
            await dialog.locator(`select[aria-label="${title} 수집"]`).selectOption(item.anchor.run_id);
            await dialog.locator(`select[aria-label="${title} 항목"]`).selectOption(JSON.stringify(item.anchor));
          }
          await dialog.locator("#rc-system").fill("vault-rotation");
          await dialog.locator("#rc-record").fill("rotation/2026-10-01/7");
          await dialog.locator("#rc-stored").fill("2026-10-01T09:30");
          await inBounds(page, `${label} form`);
          const save = dialog.locator("button", { hasText: "이력 기록" });
          await save.click();
          await dialog.locator("[role=alert]").waitFor();
          // Sent again: the same attempt keeps its id, so the server sees one record.
          await save.click();
          await dialog.waitFor({ state: "detached" });
          await settled(page, record, label);
          await card.locator("tr", { hasText: "rotation/2026-10-01/7" }).waitFor();
          // Revoked, the row stays, marked as such.
          await card.locator("tr", { hasText: "rotation/2026-09-28/123" }).locator("button[aria-label='저장 이력 철회']").click();
          await card.locator("tr", { hasText: "rotation/2026-09-28/123" }).getByText("철회됨").waitFor();
          assert.equal(await card.locator("tr", { hasText: "rotation/2026-09-28/123" }).count(), 1, `${label}: the revoked row stays`);
          const [first, second, revoke] = record.writes;
          assert.deepEqual(record.writes.map(write => `${write.method} ${write.endpoint}`), [`POST ${RECEIPTS}`, `POST ${RECEIPTS}`, `POST ${RECEIPTS}/${OLD}/revoke`], `${label}: the writes`);
          assert.equal(first.body.id, second.body.id, `${label}: one id for one record`);
          assert.match(first.body.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, `${label}: a random id`);
          assert.deepEqual(second.body, { id: first.body.id, issuer: ISSUER.anchor, vault: VAULT.anchor, source_system: "vault-rotation",
            source_record_id: "rotation/2026-10-01/7", stored_at: new Date("2026-10-01T09:30").toISOString() }, `${label}: the record`);
          assert.equal(revoke.body, undefined, `${label}: a revoke carries nothing`);
        }
        assertClean(record, label);
      } finally { await context.close(); }
    }
    console.log("PASS console storage records: an Admin links collected items to a source record, a lost response is sent again with the same id, revoking keeps the row; a Viewer changes nothing; light/dark at 390 and 1280.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
