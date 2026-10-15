"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

test("paged array reads preserve the ordinary API shape and read only the requested page", async () => {
  const calls = [], cursor = "11111111-1111-4111-8111-111111111111";
  const client = load("@/lib/dashboard-api.ts", { globals: { fetch: async (url, init) => {
    calls.push([url, init]);
    return Response.json([{ id: "one" }], { headers: { "X-Next-Cursor": cursor, "X-Page-Limit": "100" } });
  } } });
  const page = await client.apiPage("management-actions?limit=100");
  assert.equal(page.nextCursor, cursor);
  assert.equal(page.pageLimit, 100);
  assert.equal(page.data[0].id, "one");
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1].cache, "no-store");
  const ordinary = await client.api("management-actions?limit=100");
  assert.ok(Array.isArray(ordinary));
  assert.equal(ordinary[0].id, "one");
});

test("page positions move only on request and reset when the credential changes", () => {
  let state;
  const { usePageHistory } = load("@/console/pagination.tsx", { overrides: { react: {
    useState(initial) { state ??= initial; return [state, value => { state = value; }]; },
  } } });
  let page = usePageHistory("credential-a", 0);
  assert.equal(page.position, 0);
  page.next(50); page = usePageHistory("credential-a", 0);
  assert.equal(page.position, 50); assert.equal(page.page, 2);
  page.next(100); page = usePageHistory("credential-a", 0);
  page.previous(); page = usePageHistory("credential-a", 0);
  assert.equal(page.position, 50);
  page = usePageHistory("credential-b", 0);
  assert.equal(page.position, 0); assert.equal(page.page, 1);
  page.next(50); page = usePageHistory("credential-b", 0);
  page.reset(); page = usePageHistory("credential-b", 0);
  assert.equal(page.position, 0); assert.equal(page.page, 1);
});
