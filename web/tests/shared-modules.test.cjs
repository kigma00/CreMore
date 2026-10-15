// The shared modules the console reads besides its own (components/labels.tsx, components/locale.tsx,
// lib/credential-lifecycle.ts, lib/provider-metadata.ts): words for the API's codes, and the guard on provider events.
// Kept from the dashboard's tests when the dashboard was removed. Synthetic data only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const labels = load("@/components/labels");
const locale = load("@/components/locale");
const lifecycle = load("@/lib/credential-lifecycle");
const { metadataEvents, metadataPage } = load("@/lib/provider-metadata");

test("a page the server could not have produced is refused, not rendered", () => {
  assert.throws(() => metadataPage({ items: [], total: 1, offset: 0, limit: 0 }));
  assert.throws(() => metadataPage({ items: [1, 2], total: 1, offset: 0, limit: 50 }));
  assert.throws(() => metadataPage({ items: [], total: -1, offset: 0, limit: 50 }));
  assert.ok(metadataPage({ items: [1], total: 1, offset: 0, limit: 50 }));
});

test("a provider event payload must declare itself provider-reported", () => {
  const page = (changes = {}) => ({
    schema_version: 2, boundary: "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS", event_types: ["KEY_CREATED"],
    total: 1, offset: 0, limit: 50,
    items: [{ id: "r1", provider: "gcp", connection_id: "c1", run_id: "run1",
              event_type: "KEY_CREATED", event_id: "log-1", occurred_at: "2026-09-20T00:00:00Z",
              observed_at: "2026-09-21T00:00:00Z", match_basis: "AUDIT_REFERENCE", confidence: "IDENTIFIER",
              subject: { entity_id: "11111111-2222-4333-8444-555555555555", object_id: "apiKey:x", object_kind: "credential" },
              target: null, facts: [] }],
    ...changes,
  });
  assert.ok(metadataEvents(page()));
  assert.ok(metadataEvents(page({ facets: { provider: ["gcp"], event_type: ["KEY_CREATED"] } })));
  for (const flag of ["facets_truncated", "event_types_truncated"]) {
    for (const value of [true, false]) assert.equal(metadataEvents(page({ [flag]: value }))[flag], value);
    for (const value of [null, 1, "false"]) assert.throws(() => metadataEvents(page({ [flag]: value })), /METADATA_FACETS_INVALID/);
  }
  for (const facets of [null, {}, { provider: [null], event_type: [] }, { provider: [], event_type: "KEY_CREATED" }]) {
    assert.throws(() => metadataEvents(page({ facets })), /METADATA_FACETS_INVALID/);
  }
  // Without the boundary these rows would render beside the local action history, where a provider's record would
  // read as something a person did.
  assert.throws(() => metadataEvents(page({ boundary: "AUDIT" })), /METADATA_EVENTS_INVALID/);
  assert.throws(() => metadataEvents(page({ event_types: "KEY_CREATED" })), /METADATA_EVENTS_INVALID/);
  for (const bad of [{ provider: "nowhere" }, { match_basis: "TRUSTED" }, { confidence: "CERTAIN" },
                     { subject: { entity_id: "e", object_id: "x", object_kind: "invented" } }]) {
    assert.throws(() => metadataEvents(page({ items: [{ ...page().items[0], ...bad }] })), /METADATA_EVENTS_INVALID/, JSON.stringify(bad));
  }
  // A subject the collection did not resolve is null, and that is allowed.
  assert.ok(metadataEvents(page({ items: [{ ...page().items[0], subject: null }] })));
});

test("run reasons read in words with the code kept; an unknown code stays itself", () => {
  assert.equal(labels.metadataReasonsText(["SOME_PROVIDER_CODE"], "ko"), "SOME_PROVIDER_CODE");
  assert.match(labels.metadataReasonsText(["METADATA_COLLECTION_PAUSE_EXPIRED"], "ko"), /^일시중지가 실행 수명.* \(METADATA_COLLECTION_PAUSE_EXPIRED\)$/);
});

test("Azure credential types have their own names", () => {
  for (const [type, en, ko] of [["AZURE_DEVOPS_PAT", "Azure DevOps personal access token", "Azure DevOps 개인 액세스 토큰"],
    ["AZURE_SAS_TOKEN", "Azure Storage SAS token", "Azure Storage SAS 토큰"],
    ["AZURE_ENTRA_CLIENT_SECRET", "Microsoft Entra client secret", "Microsoft Entra 클라이언트 시크릿"]]) {
    assert.equal(labels.credentialTypeLabel(type, "en"), en);
    assert.equal(labels.credentialTypeLabel(type, "ko"), ko);
  }
});

test("localized enum labels and dates are resilient", () => {
  assert.equal(locale.enumLabel("NOT_VERIFIED", "ko"), "미검증");
  assert.equal(locale.enumLabel("ENRICHING", "ko"), "정보 보강 중");
  assert.equal(locale.enumLabel("ACTION_REQUIRED", "en"), "Action required");
  assert.equal(locale.when("invalid-date", "ko"), "—");
  assert.notEqual(locale.when("2026-09-07T00:00:00Z", "ko"), locale.when("2026-09-07T00:00:00Z", "en"));
});

test("every authentication failure has words in both languages", () => {
  for (const code of ["AUTH_WAITING", "AUTH_EXPIRED", "AUTH_LIFETIME_TOO_SHORT", "IDENTITY_MISMATCH", "SECRET_UNAVAILABLE",
    "SOURCE_SECRET_UNAVAILABLE", "SOURCE_PROFILE_INVALID", "REAUTH_REQUIRED"]) {
    for (const language of ["ko", "en"]) {
      const words = lifecycle.connectionAuthReason(code, language);
      assert.ok(words.length > 0 && !words.includes(code), `${code} ${language}: ${words}`);
    }
  }
});
