// Owner & team assignment: which team a credential falls to, what each team still has to do, what each filter shows
// and how a large selection is sent. Synthetic records and directory only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/assign/model.ts");
// Values made in the loaded module's realm compare by structure once they are plain JSON.
const plain = value => JSON.parse(JSON.stringify(value));
const NOW = Date.parse("2026-09-29T03:00:00Z");

const record = (id, extra = {}) => ({
  id, credential_id: id, finding_id: `f-${id}`, entity_id: null, provider: "github", credential_type: "GITHUB_TOKEN", category: "token", kind: "token",
  name: `token ${id}`, hint: null, exposed: true, status: "pending", workflow_status: "OPEN", risk: "high", acknowledged_at: null, resolved_at: null,
  verification: { state: "unknown", at: null, basis: null, reason: null }, owner: null, issuer: null,
  exposures: [{ source_type: "github", resource_name: `org/repo-${id}`, location: "a.env", line: 1, snippet: null, visibility: "private", current: true, first_seen_at: null, last_seen_at: null }],
  exposure_count: 1, location_count: 1, first_seen_at: null, last_seen_at: null, created_at: null, expires_at: null, expiry: "unknown", last_used: null, scopes: null,
  vault: { state: "unknown", where: [], basis: "", reasons: [], absence_basis: null }, tags: [], stage: null, steps: {}, contact: null, annotations_revision: 0,
  review: null, issued: null, ...extra,
});
const review = (status, extra = {}) => ({ status, assigned_team: null, due_at: null, closed_reason: "", revision: 1, updated_at: null, ...extra });
const PEOPLE = [
  { id: "p1", name: "이데모", email: "demo.lee@example.test", department: "플랫폼팀", title: null, state: "ACTIVE", sources: [] },
  { id: "p2", name: "김퇴사", email: "gone.kim@example.test", department: "플랫폼팀", title: null, state: "DEPARTED", sources: [] },
  { id: "p3", name: "박보안", email: "sec.park@example.test", department: "보안팀", title: null, state: "ACTIVE", sources: [] },
];

test("a credential's team is its review's, else its owner's, else the owner's IdP department", () => {
  const rows = model.assignRows([
    record("a", { review: review("IN_PROGRESS", { assigned_team: "인프라팀" }), owner: { name: "이데모", team: null, basis: "CODEOWNERS" } }),
    record("b", { owner: { name: null, team: "데이터팀", basis: "RESPONSIBLE_TEAM" } }),
    record("c", { owner: { ...PEOPLE[0], person_ref: "verified-person", team: null, basis: "ASSIGNED" } }),
    record("d"),
    record("x", { exposed: false, finding_id: null }),
  ], PEOPLE, NOW);
  assert.deepEqual(plain(rows.map(row => [row.c.id, row.team, row.owner, row.status])), [
    ["a", "인프라팀", "이데모", "IN_PROGRESS"], ["b", "데이터팀", null, "OPEN"], ["c", "플랫폼팀", "이데모", "OPEN"], ["d", null, null, "OPEN"]]);
  assert.equal(rows[2].person.name, "이데모");
});

test("a review is overdue only past its due date and while it is not completed", () => {
  const rows = model.assignRows([
    record("late", { review: review("WAITING_OWNER", { assigned_team: "보안팀", due_at: "2026-09-28T00:00:00Z" }) }),
    record("soon", { review: review("WAITING_OWNER", { assigned_team: "보안팀", due_at: "2026-10-02T00:00:00Z" }) }),
    record("closed", { review: review("CLOSED", { assigned_team: "보안팀", due_at: "2026-09-01T00:00:00Z", closed_reason: "CREDENTIAL_RETIRED" }) }),
  ], PEOPLE, NOW);
  assert.deepEqual(plain(rows.map(row => row.overdue)), [true, false, false]);
});

test("confirmed removal leaves assignment counts, a recurrence keeps its previous owner", () => {
  const active = record("a", { owner: { name: "demo.lee@example.test", team: "플랫폼팀", basis: "ASSIGNED" } });
  const removed = { ...active, exposure_state: "REMOVED", all_locations_removed: true };
  assert.equal(model.assignRows([removed], PEOPLE, NOW).length, 0);
  const again = { ...removed, exposure_state: "ACTIVE", all_locations_removed: false };
  const rows = model.assignRows([again], PEOPLE, NOW);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].owner, active.owner.name);
  assert.equal(rows[0].c.id, active.id);
});

test("automatic response states drive assignment waiting counts and name the requested responder", () => {
  const rows = model.assignRows([record("a", { owner: { ...PEOPLE[0], person_ref: "verified-person", basis: "TICKET_RESPONDER" }, response: { state: "WAITING_OWNER", version: 1,
    current: { assigned_to: "demo.lee@example.test", recipient: { ...PEOPLE[0], person_ref: "verified-person" } } }, review: review("OPEN") })], PEOPLE, NOW);
  assert.equal(rows[0].status, "WAITING_OWNER");
  assert.equal(rows[0].owner, PEOPLE[0].name);
  assert.equal(rows[0].team, "플랫폼팀");
  assert.equal(model.teamsOf(rows, PEOPLE)[0].waiting, 1);
  assert.equal(model.shownRows(rows, "waiting", null, "", c => c.name).length, 1);
});

test("explicit unassignment remains unowned even while the prior ticket awaits its recipient", () => {
  const prior = { ...PEOPLE[0], person_ref: "verified-person" };
  const c = record("unassigned", { owner: null, response: { state: "WAITING_OWNER", version: 1,
    current: { assigned_to: prior.email, recipient: prior, team: "Old team" } } });
  const [row] = model.assignRows([c], PEOPLE, NOW);
  assert.equal(row.owner, null);
  assert.equal(row.person, undefined);
  assert.equal(row.team, null);
  assert.equal(load("@/console/records.ts").ownerless(c), true);
  assert.equal(model.shownRows([row], "unowned", null, "", item => item.name).length, 1);
  assert.equal(c.response.current.recipient.name, prior.name, "the requested recipient remains in cycle history");
});

test("each team counts what still needs action, and its IdP members who have not left", () => {
  const rows = model.assignRows([
    record("a", { owner: { ...PEOPLE[0], person_ref: "verified-person", team: null, basis: "ASSIGNED" } }),
    record("b", { review: review("WAITING_OWNER", { assigned_team: "플랫폼팀", due_at: "2026-09-20T00:00:00Z" }) }),
    record("c", { status: "done" }),
    record("d"),
  ], PEOPLE, NOW);
  const teams = model.teamsOf(rows, PEOPLE);
  assert.deepEqual(plain(teams), [
    { team: "플랫폼팀", open: 2, unowned: 1, waiting: 1, overdue: 1, done: 0, members: 1 },
    { team: "", open: 1, unowned: 1, waiting: 0, overdue: 0, done: 1, members: 0 },
  ]);
});

test("the filters, the team filter and the search narrow the rows", () => {
  const rows = model.assignRows([
    record("a", { owner: { ...PEOPLE[0], person_ref: "verified-person", team: null, basis: "ASSIGNED" } }),
    record("b", { review: review("WAITING_OWNER", { assigned_team: "보안팀", due_at: "2026-09-20T00:00:00Z" }) }),
    record("c", { status: "done" }),
  ], PEOPLE, NOW);
  const ids = (filter, team = null, q = "") => plain(model.shownRows(rows, filter, team, q, c => c.name).map(row => row.c.id));
  assert.deepEqual(ids("open"), ["a", "b"]);
  assert.deepEqual(ids("all"), ["a", "b", "c"]);
  assert.deepEqual(ids("unowned"), ["b"]);
  assert.deepEqual(ids("noteam"), []);
  assert.deepEqual(ids("waiting"), ["b"]);
  assert.deepEqual(ids("overdue"), ["b"]);
  assert.deepEqual(ids("all", model.NO_TEAM), ["c"]);
  assert.deepEqual(ids("open", "플랫폼팀"), ["a"]);
  assert.deepEqual(ids("open", null, "REPO-B"), ["b"]);
  assert.deepEqual(ids("open", null, "이데모"), ["a"]);
});

test("a team literally named '-' is a team, and the no-team filter is no team's name", () => {
  const rows = model.assignRows([record("a", { review: review("IN_PROGRESS", { assigned_team: "-" }) }), record("b")], [], NOW);
  const ids = team => plain(model.shownRows(rows, "all", team, "", c => c.name).map(row => row.c.id));
  assert.deepEqual(ids("-"), ["a"]);
  assert.deepEqual(ids(model.NO_TEAM), ["b"]);
});

test("the history reads a review's team from its audit note, quotes and all", () => {
  const tabs = load("@/console/views/credentials/tabs.tsx");
  assert.equal(tabs.reviewTeam('team="결제팀" due=- reason=CREDENTIAL_RETIRED'), "결제팀");
  assert.equal(tabs.reviewTeam('team="pay \\"ops\\" due=2020" due=-'), 'pay "ops" due=2020');
  assert.equal(tabs.reviewTeam('team="" due=-'), "");
  assert.equal(tabs.reviewTeam("team=payments due=-"), "");  // not the quoted form
  assert.equal(tabs.reviewTeam(null), "");
});

test("a selection goes to the server a hundred findings at a time", () => {
  const items = Array.from({ length: 230 }, (_, n) => n);
  assert.deepEqual(plain(model.batches(items).map(chunk => chunk.length)), [100, 100, 30]);
  assert.deepEqual(plain(model.batches([])), []);
});


test("a matching display name or email never assigns an IdP department without a server-bound person ref", () => {
  const rows = model.assignRows([record("same-name", { owner: { name: "이데모", basis: "CODEOWNERS" } }),
    record("same-email", { owner: { name: "demo.lee@example.test", basis: "ASSIGNED" } })], PEOPLE, NOW);
  assert.deepEqual(plain(rows.map(row => [row.team, row.person ?? null])), [[null, null], [null, null]]);
});
