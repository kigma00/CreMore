// Run every synthetic browser proof of the console (no server, provider or
// deployment) one after another in headless Chrome, and fail if any of them fails.
//
//   npm run test:browser                 # all synthetic proofs
//   npm run test:browser -- console-list # only proofs whose name matches
"use strict";
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const output = fs.mkdtempSync(path.join(os.tmpdir(), "cremore-browser-proofs-"));
const proofs = [
  ["console-access"],
  ["console-account"],
  ["console-credential-permissions"],
  ["console-auth-first"],
  ["console-edition-entry"],
  ["console-audit"],
  ["console-deletion"],
  ["console-directory-refresh"],
  ["console-gcp-oauth"],
  ["console-github-export"],
  ["console-github-app"],
  ["console-integration-edit"],
  ["console-integration-refresh"],
  ["console-independent-approval"],
  ["console-late"],
  ["console-list"],
  ["console-literal-scope"],
  ["console-response"],
  ["console-response-channels"],
  ["console-response-link"],
  ["console-responder"],
  ["console-metadata-popover"],
  ["console-notion-rows"],
  ["console-notion-webhooks"],
  ["console-pagination"],
  ["console-receipts"],
  ["console-rescan"],
  ["console-search"],
  ["console-setup"],
  ["console-shell"],
  ["console-timezone"],
  ["console-usage-status"],
];

const filter = process.argv.slice(2);
const selected = proofs.filter(([name]) => !filter.length || filter.some(term => name.includes(term)));
if (!selected.length) {
  console.error(`no browser proof matches ${filter.join(", ")}`);
  process.exit(1);
}

const failures = [];
for (const [name, ...args] of selected) {
  const started = Date.now();
  const result = spawnSync(process.execPath, [path.join(__dirname, `${name}.browser.cjs`), ...args], {
    encoding: "utf8",
    // A proof keeps its failure screenshots here (tests/console-proof.cjs withScreenshot).
    env: { ...process.env, CREMORE_PROOF_ARTIFACTS: output },
    // The console shell proof walks every screen in twelve layouts: about three minutes on a slow machine.
    timeout: 10 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  if (result.status === 0) {
    console.log(`ok ${name} (${seconds}s)`);
  } else {
    failures.push(name);
    console.log(`not ok ${name} (${seconds}s, exit ${result.status ?? result.signal})`);
    console.log(`${result.stdout || ""}${result.stderr || ""}`.trim().split("\n").slice(-40).join("\n"));
  }
}
console.log(`${selected.length - failures.length}/${selected.length} browser proofs passed; artifacts in ${output}`);
process.exit(failures.length ? 1 : 0);
