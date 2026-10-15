"use strict";
// The departed-owner page says which listing a PARTIAL check could not read whole (cremore/identity/leavers.py).
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const { listingReason } = load("@/console/views/leavers/page.tsx");
const ko = (text) => text;
const en = (_ko, text) => text;

test("a cut listing reads as which listing and how it was cut", () => {
  assert.equal(listingReason("ISSUED_CREDENTIALS_LIMIT_REACHED", ko), "발급 목록 한도 초과");
  assert.equal(listingReason("COVERAGE_REPORT_LIMIT_REACHED", en), "Vault comparison report past its limit");
  assert.equal(listingReason("IDP_PEOPLE_CHANGED_WHILE_READ", ko), "IdP 사람 목록 읽는 중 변경");
  assert.equal(listingReason("SOMETHING_NEW", ko), "SOMETHING_NEW");
});

test("departed people are named from every page of the directory, not the first 500", async () => {
  const { everyPerson } = load("@/console/views/leavers/page.tsx");
  const asked = [];
  const pages = {
    "people?limit=500": { items: [{ id: "a", refs: ["a"] }], total: 2, next_cursor: "c/1+" },
    "people?limit=500&cursor=c%2F1%2B": { items: [{ id: "z", refs: ["z"] }], total: 2, next_cursor: null },
  };
  const all = await everyPerson("people?limit=500", async (path) => { asked.push(path); return pages[path]; });
  assert.deepEqual(asked, Object.keys(pages));
  assert.deepEqual(Array.from(all.items, (person) => person.id), ["a", "z"]);
});
