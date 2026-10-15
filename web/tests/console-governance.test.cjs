// Tickets and management actions on a credential's remediation tab: a new ticket's defaults, what the create
// request carries, and an update that sends every reviewed field again (the API reads a missing one as cleared).
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const governance = load("@/console/views/credentials/governance.tsx");
const plain = value => JSON.parse(JSON.stringify(value));
const L = (ko, en) => en;
const ME = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const NOW = Date.parse("2026-09-29T03:00:00Z");

test("a new ticket is due in a week and owned by whoever opens it when the API names them by reference", () => {
  const draft = plain(governance.blankTicket(ME, NOW));
  assert.equal(draft.owner_id, ME);
  assert.equal(Date.parse(draft.review_due_at) - NOW, 7 * 86_400_000);  // a local datetime-local value, the same instant
  assert.equal(governance.blankTicket("alice", NOW).owner_id, "");  // a subject, not a reference: no owner yet
  assert.equal(governance.blankTicket(undefined, NOW).owner_id, "");
});

test("the create request carries the playbook, and a custom one its steps and approval rule", () => {
  const draft = { ...governance.blankTicket(ME, NOW), responsible_team: " 보안팀 " };
  const { body } = governance.ticketBody(draft, "f-1", L);
  assert.deepEqual(plain(body), {
    finding_id: "f-1", template_id: "PUBLIC_EXPOSURE", priority: "HIGH", service_impact: "UNKNOWN",
    review_due_at: new Date(Date.parse(draft.review_due_at)).toISOString(), responsible_team: "보안팀", owner_id: ME,
  });
  assert.match(governance.ticketBody({ ...draft, template_id: "CUSTOM" }, "f-1", L).problem, /review step/);
  const custom = governance.ticketBody({ ...draft, template_id: "CUSTOM", custom_steps: ["SET_FOLLOW_UP"], independent: false }, "f-1", L).body;
  assert.deepEqual(plain({ steps: custom.custom_steps, rule: custom.customization }), { steps: ["SET_FOLLOW_UP"], rule: { approval_rule: "NONE", conditions: [] } });
  assert.match(governance.ticketBody({ ...draft, review_due_at: "" }, "f-1", L).problem, /review date/);
  assert.match(governance.ticketBody({ ...draft, owner_id: "alice" }, "f-1", L).problem, /owner/);
});

test("an update sends every reviewed field again, with the version it was read at", () => {
  const ticket = { id: "t-1", version: 3, status: "IN_PROGRESS", priority: "CRITICAL", service_impact: "LIMITED", responsible_team: "보안팀",
    owner_id: ME, review_due_at: "2026-10-06T03:00:00Z", steps: [{ code: "SET_FOLLOW_UP", status: "TODO", reviewed_by: "x" }] };
  const body = plain(governance.ticketUpdate(ticket, { status: "RESOLVED", steps: [{ code: "SET_FOLLOW_UP", status: "REVIEWED" }] }));
  assert.deepEqual(body, { expected_version: 3, status: "RESOLVED", priority: "CRITICAL", service_impact: "LIMITED", responsible_team: "보안팀",
    review_due_at: "2026-10-06T03:00:00Z", owner_id: ME, steps: [{ code: "SET_FOLLOW_UP", status: "REVIEWED" }] });
  // Without an owner before or after, none is sent rather than an empty one.
  assert.equal("owner_id" in plain(governance.ticketUpdate({ ...ticket, owner_id: undefined }, {})), false);
  // "Unassigned" clears the owner: the API reads a field left out as cleared.
  assert.equal("owner_id" in plain(governance.ticketUpdate(ticket, { owner_id: "" })), false);
  // A security review recorded through the API or the earlier panel goes back as it is, never dropped by a save.
  const review = { service_name: "billing", storage_method: "SECRET_MANAGER_REFERENCE" };
  assert.deepEqual(plain(governance.ticketUpdate({ ...ticket, security_review: review }, {})).security_review, review);
  assert.equal("security_review" in plain(governance.ticketUpdate(ticket, {})), false);
});
