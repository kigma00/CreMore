"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const people = load("@/console/people.ts");
const person = { id: "row", person_ref: "00000000-0000-4000-8000-000000000600", name: "Same name", email: "person600@example.test",
  department: "Operations", title: null, state: "ACTIVE", sources: [], selectable: true };

test("directory search is bounded per remote page and preserves opaque cursor and query", () => {
  const path = people.peoplePath(" Same & +name ", "opaque+/=cursor");
  const url = new URL(path, "https://example.test/");
  assert.equal(url.searchParams.get("q"), "Same & +name");
  assert.equal(url.searchParams.get("limit"), "25");
  assert.equal(url.searchParams.get("cursor"), "opaque+/=cursor");
});

test("only a current selectable active IdP person with stable reference and email can be chosen", () => {
  assert.equal(people.selectablePerson(person), true);
  for (const change of [{ person_ref: "" }, { selectable: false }, { state: "DEPARTED" }, { state: "PENDING" }, { email: null }]) {
    assert.equal(people.selectablePerson({ ...person, ...change }), false);
  }
  assert.equal(people.selectablePerson(null), false);
});

test("owner display and recipient addresses never match an unrelated person by display name", () => {
  assert.equal(people.assignedPerson({ owner: { name: "Same name", basis: "CODEOWNERS" } }), undefined);
  const assigned = people.assignedPerson({ owner: { name: "Same name", person_ref: person.person_ref, email: "server@example.test", department: "Verified team" } });
  assert.equal(assigned.email, "server@example.test");
  assert.equal(assigned.department, "Verified team");
  assert.deepEqual(JSON.parse(JSON.stringify(people.addressesOf([person], [person.name]))), []);
  assert.deepEqual(JSON.parse(JSON.stringify(people.addressesOf([person], [person.person_ref]))), [person.email]);
});
