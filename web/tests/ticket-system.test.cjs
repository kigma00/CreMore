// The company's ticket system, where an owner's approval can be asked: what the integrations card says, the setup a
// save sends (the plain values, and only the secrets typed now: a blank one keeps the saved one), and the state of an
// answer that came from someone other than the account asked.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const tickets = load("@/console/views/integrations/ticket-system.tsx");
const plans = load("@/console/views/approvals/model.ts");
const plain = value => JSON.parse(JSON.stringify(value));
const L = (ko, en) => en;
const FIELDS = [
  { name: "url", kind: "url" }, { name: "client_id", kind: "text" }, { name: "client_secret", kind: "secret" },
  { name: "username", kind: "text" }, { name: "password", kind: "secret" }, { name: "entity_id", kind: "number" },
];

test("the card names the ticket system an owner can be asked in", () => {
  assert.equal(tickets.ticketState(undefined, L), "Not set up");
  assert.equal(tickets.ticketState({ system: null, label: null }, L), "Not set up");
  assert.equal(tickets.ticketState({ system: "servicedesk", label: "Service Desk" }, L), "Service Desk");
});

test("a save sends the plain values and only the secrets typed now", () => {
  const secret = "plugin" + "-client-secret";  // built at run time: nothing secret-shaped sits in the source
  const form = { system: "servicedesk", values: { url: " https://tickets.example.com/desk ", client_id: "cremore", client_secret: ` ${secret} `,
    username: "cremore-svc", password: "", entity_id: "0" } };
  assert.deepEqual(plain(tickets.ticketBody(form, FIELDS)), {
    system: "servicedesk", values: { url: "https://tickets.example.com/desk", client_id: "cremore", username: "cremore-svc", entity_id: "0" },
    secrets: { client_secret: secret } });
  assert.deepEqual(plain(tickets.ticketBody({ system: "", values: { url: "x" } }, FIELDS)), { system: null });
});

test("the window puts an address on its own line and the other values two to a line", () => {
  const names = tickets.rows([...FIELDS, { name: "category_id", kind: "number" }]).map(row => row.map(field => field.name));
  assert.deepEqual(plain(names), [["url"], ["client_id", "client_secret"], ["username", "password"], ["entity_id", "category_id"]]);
});

test("an answer from another account than the one asked is its own state", () => {
  assert.deepEqual(plain(plans.OWNER_WORDS.ANSWERED_BY_OTHER), ["다른 사람이 응답함", "Answered by someone else"]);
  assert.equal(plans.OWNER_TONE.ANSWERED_BY_OTHER, "warn");
  assert.deepEqual(plain(plans.OWNER_WORDS.NOT_INDEPENDENT), ["보안 측과 구별 안 됨", "Not independent"]);
  assert.equal(plans.OWNER_TONE.NOT_INDEPENDENT, "warn");
  assert.deepEqual(plain(plans.OWNER_WORDS.EXPIRED), ["기한 지남", "Expired"]);  // a link or a ticket
});
