"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load } = require("./load-module.cjs");
const people = load("@/console/people.ts");
const access = load("@/console/views/credentials/access.tsx");
const locale = load("@/components/locale.tsx");
const plain = value => JSON.parse(JSON.stringify(value));
const at = "2026-10-01T12:00:00Z";
const place = (key, extra = {}) => ({ exposure_id: key, source_type: "github", repository: "same/repo", path: "file.env", commit: "",
  source_connection_id: `connection-${key}`, source_label: `Host ${key}`, access_key: key, context_status: "OBSERVED", codeowners: {}, author: {}, ...extra });
const repository = (key, extra = {}) => ({ ...place(key), status: "OBSERVED", basis: "GITHUB_REPOSITORY_COLLABORATORS", completeness: "COMPLETE",
  observed_at: at, evidence_kind: "PROVIDER_COLLABORATORS", visibility: "PRIVATE", limitations: ["NOT_ACCESS_HISTORY"],
  people: [{ login: "same-login", name: "Same name", role: "read", read_access: "REPORTED" }], ...extra });
const context = (extra = {}) => ({ status: "COMPLETE", collected_at: at, locations: [place("a"), place("b")], repositories: [repository("a"), repository("b")], reasons: [], ...extra });
const html = (ctx, atIndex = 0) => renderToStaticMarkup(React.createElement(locale.LocaleContext.Provider, { value: "en" },
  React.createElement(access.AccessList, { context: ctx, place: ctx.locations[atIndex] })));

test("same login/repository on two connections stays separate, joined only by exact access key", () => {
  const ctx = context();
  assert.equal(people.accessPeople(ctx).length, 2);
  assert.equal(people.locationAccess(ctx, ctx.locations[1]).source_connection_id, "connection-b");
  for (const altered of [{ access_key: "a" }, { source_connection_id: "connection-a" }, { source_type: "gitlab" }, { repository: "other/repo" }]) {
    assert.equal(people.locationAccess(ctx, { ...ctx.locations[1], ...altered }), undefined);
  }
  assert.equal(people.locationAccess({ ...ctx, repositories: [...ctx.repositories, ctx.repositories[0]] }, ctx.locations[0]), undefined);
});

test("legacy observations cannot borrow an identically named repository on another host", () => {
  const ctx = context({ locations: [place("a", { access_key: undefined, source_connection_id: undefined })] });
  assert.equal(people.locationAccess(ctx, ctx.locations[0]), undefined);
  assert.deepEqual(plain(people.accessPeople(ctx)), []);
  const view = html(ctx);
  assert.match(view, /older observation has no connection identity/);
  assert.doesNotMatch(view, /Same name|provider returned no accounts/i);
  const rows = people.accessRows(ctx);
  assert.equal(rows[1][rows[0].indexOf("status")], "REFRESH_REQUIRED");
});

test("partial failed pages keep observed accounts, unknown reads stay unknown, and export preserves limits", () => {
  const ctx = context({ location_count: 102, queried_locations: 5, unqueried_locations: 97, omitted_locations: 2,
    repositories: [repository("a", { status: "FORBIDDEN", completeness: "PARTIAL", truncated: true,
    basis: "GITLAB_PROJECT_MEMBERS", evidence_kind: "PROVIDER_MEMBERSHIP", visibility: "PUBLIC",
    limitations: ["MEMBER_PAGE_UNAVAILABLE", "MEMBERSHIP_NOT_EFFECTIVE_READ_ACCESS"],
    people: [{ login: "=cmd", name: null, role: "guest", read_access: "UNKNOWN" }] }), repository("b")] });
  const view = html(ctx);
  assert.match(view, /partial list|next page of the list could not be read/);
  assert.match(view, /Public · anonymous readers not enumerated/);
  assert.match(view, />Unknown<\/td>/);
  assert.match(view, /not proof of actual viewing/);
  const rows = people.accessRows(ctx), index = name => rows[0].indexOf(name);
  assert.equal(rows[1][index("source_connection_id")], "connection-a");
  assert.equal(rows[1][index("path")], "file.env");
  assert.equal(rows[1][index("status")], "FORBIDDEN");
  assert.equal(rows[1][index("completeness")], "PARTIAL");
  assert.equal(rows[1][index("read_access")], "UNKNOWN");
  assert.equal(rows[1][index("omitted_locations")], "2");
  assert.equal(rows[1][index("unqueried_locations")], "97");
  assert.match(load("@/console/text.ts").csvText(rows), /'=cmd/);
});

test("unsupported, capped and failed locations never show a zero-person conclusion or stale people", () => {
  for (const status of ["UNSUPPORTED", "LIMIT_REACHED", "UNAVAILABLE", "BLOCKED"]) {
    const ctx = context({ locations: [place("a", { context_status: status })], repositories: [repository("a", { status,
      completeness: status === "UNSUPPORTED" ? "UNSUPPORTED" : "UNKNOWN", observed_at: null })] });
    const view = html(ctx);
    assert.doesNotMatch(view, /Same name|0 people|provider returned no accounts/i);
    assert.equal(people.accessPeople(ctx).length, 0);
    const rows = people.accessRows(ctx);
    assert.equal(rows.length, 2, "unavailable locations remain in CSV even without a person");
    assert.equal(rows[1][rows[0].indexOf("status")], status);
  }
});

test("complete empty lists are distinguished from missing access evidence", () => {
  const ctx = context({ repositories: [repository("a", { people: [] }), repository("b")] });
  assert.match(html(ctx), /provider returned no accounts/i);
  assert.match(html(ctx), /does not rule out public or shared-link access/);
  const missing = context({ repositories: [] });
  assert.doesNotMatch(html(missing), /provider returned no accounts/i);
  assert.match(html(missing), /provider could not return the list/i);
  assert.equal(people.accessRows(missing)[1][7], "UNAVAILABLE");
});

test("group, public and policy principals retain permission/effect evidence and never become notification people", () => {
  const ctx = context({ locations: [place("a")], repositories: [repository("a", { basis: "AWS_S3_POLICY_ACL", evidence_kind: "PROVIDER_GRANTS", people: [
    { login: "group-1", principal_id: "stable-group-id", principal_kind: "GROUP", name: "Team group", permission: "s3:GetObject", effect: "ALLOW", read_access: "UNKNOWN" },
    { login: "group-1", principal_id: "stable-group-id", principal_kind: "GROUP", name: "Team group", permission: "s3:*", effect: "DENY", read_access: "UNKNOWN" },
    { login: "*", principal_kind: "PUBLIC", name: "Public", permission: "read", effect: "RESTRICT", read_access: "UNKNOWN" },
  ] })] });
  const view = html(ctx);
  assert.match(view, /Group · members not enumerated/);
  assert.match(view, /Deny entry/);
  assert.match(view, /Restriction entry/);
  assert.match(view, /AWS S3 policy and ACL/);
  assert.doesNotMatch(view, /Provider reported/);
  assert.deepEqual(plain(load("@/console/views/credentials/tabs.tsx").accessTargets(ctx, (ko, en) => en)), []);
  const rows = people.accessRows(ctx);
  assert.equal(rows.length, 4);
  assert.equal(rows[2][rows[0].indexOf("effect")], "DENY");
  assert.equal(rows[1][rows[0].indexOf("principal_id")], "stable-group-id");
});
