// A token that rotates itself (GitLab) in the console: how the method is named, and what a connection says
// when reading the token or rotating it failed. Synthetic connections only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const copy = load("@/console/views/integrations/copy.ts");
const L = (ko, en) => ko;

const gitlab = renewal => ({
  id: "g1", provider: "gitlab", edition: "cloud", name: "GitLab · group 42", status: "ACTIVE", revision: 4,
  purposes: ["exposure", "inventory"], plans: { inventory: {} }, auth_method: "token", renewal: "ROTATES",
  credential: { roles: ["credential"], reference: false }, children: [], target: { scope: "group", id: "42" },
  checks: { results: {}, checked_at: "2026-09-29T02:00:00Z", requested_at: "2026-09-29T01:00:00Z", job_id: null, stale: false, error: null, renewal },
});

test("a token that renews itself is named so, with what it needs", () => {
  const tag = copy.renewalTag({ id: "token", renewal: "ROTATES" }, L);
  assert.equal(tag.text, "자동 교체");
  assert.match(tag.tip, /self_rotate/);
  assert.match(copy.methodHint("gitlab", { id: "token", renewal: "ROTATES" }, L), /self_rotate 범위를 주면/);
  assert.equal(model.detailText("TOKEN_RENEWED_BY_HAND", L), "없으면 만료 전에 직접 새 토큰을 넣어야 함");
});

test("a failed rotation or token check asks for a person; a quiet one does not", () => {
  assert.equal(model.rowState(gitlab({ state: "OK", action: "inspect", code: null }), [], L).tone, "ok");
  const failed = model.rowState(gitlab({ state: "FAILED", action: "renew", code: "GITLAB_ROTATION_UNCERTAIN" }), [], L);
  assert.equal(failed.tone, "warn");
  assert.equal(failed.fix, "reauth");
  assert.match(failed.note, /^자동 교체 실패 · 교체 응답을 확인하지 못했습니다/);
  const revoked = model.rowState(gitlab({ state: "FAILED", action: "inspect", code: "GITLAB_TOKEN_REVOKED" }), [], L);
  assert.match(revoked.note, /^토큰 확인 실패 · 저장한 토큰이 폐기됐거나 만료됐습니다/);
  assert.match(model.rowState(gitlab({ state: "FAILED", action: "renew", code: "RENEWAL_INTERRUPTED" }), [], L).note, /중간에 끊겼습니다/);
});
