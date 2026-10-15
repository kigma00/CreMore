"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

const L = (ko, en) => en;

test("the Other settings line says how many domains are verified, or how many wait", () => {
  const domains = load("@/console/views/integrations/domains.tsx");
  assert.equal(domains.domainState(undefined, L), "Not set up");
  assert.equal(domains.domainState({ domains: [], limit: 100 }, L), "Not set up");
  assert.equal(domains.domainState({ domains: [{ status: "PENDING" }, { status: "LAPSED" }], limit: 100 }, L), "2 awaiting");
  assert.equal(domains.domainState({ domains: [{ status: "VERIFIED" }, { status: "PENDING" }], limit: 100 }, L), "1 verified");
  // Every status and DNS answer the server gives reads in words.
  for (const status of ["PENDING", "VERIFIED", "LAPSED"]) assert.ok(domains.STATUS_WORDS[status]);
  for (const result of ["VERIFIED", "TXT_NOT_FOUND", "TXT_MISMATCH", "DNS_UNAVAILABLE"]) assert.ok(domains.RESULT_WORDS[result]);
});

test("domain verification is an Other settings item an admin opens, named as in the design", () => {
  const page = source("@/console/views/integrations/page.tsx");
  assert.match(page, /icon: "globe", title: L\("도메인 검증", "Domain verification"\)/);
  assert.match(page, /session\.role === "Admin" \? setDomainsOpen\(true\)/);
  // Analysts read which domains are verified; the record to publish comes only with the admin's view.
  const modal = source("@/console/views/integrations/domains.tsx");
  assert.match(modal, /DOMAINS_PATH = "settings\/domains"/);
  assert.match(modal, /DOMAIN_STATUS_PATH = "domains"/);
  // Removing a domain or renewing its value takes a second press.
  assert.match(modal, /armed === `remove:\$\{domain\.name\}`/);
  assert.match(modal, /armed === `renew:\$\{domain\.name\}`/);
});
