// Signing in to IAM Identity Center from the console: which AWS sign-in problems offer it next to the command, and
// how each way it can end reads. Synthetic identity views only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const identity = load("@/console/views/integrations/aws-identity.tsx");
const L = (ko, en) => ko;

const view = extra => ({ api: { state: "NO_CREDENTIALS" }, worker: null, sign_in: null, worker_stale: false, same_identity: false,
  approvable: null, approved: null, hold: null, policy: {}, permission_set_policy: null, ...extra });

test("Roles Anywhere identifies certificate renewal without offering a human sign-in", () => {
  const api = { state: "READY", kind: "IAM_ROLE", account_id: "123456789012", credential_source: "roles-anywhere",
    renewal_health: { state: "EXPIRING", certificate_expires_at: "2026-11-01T00:00:00Z" } };
  for (const say of [L, (_ko, en) => en]) {
    assert.match(identity.identityText(view({ api }), say), /Roles Anywhere/);
    const failed = { ...api, renewal_health: { state: "ERROR", error_code: "AWS_ROLES_ANYWHERE_HELPER_CHANGED" } };
    const issue = identity.identityIssue(view({ api: failed }), say, true);
    assert.equal(issue.signIn, undefined);
    assert.match(issue.fix, /인증서|certificate/);
  }
});

test("a missing or expired Identity Center sign-in can be done here as well as by the command", () => {
  const none = identity.identityIssue(view({ sign_in: { reason: "NO_CACHED_SIGN_IN", requested_profile: "cremore" } }), L, true);
  assert.equal(none.signIn, true);
  assert.equal(none.code, "aws sso login --use-device-code --profile cremore");
  assert.match(none.fix, /여기서 IAM Identity Center에 로그인하거나/);
  const expired = identity.identityIssue(view({ api: { state: "READY" }, hold: "AWS_LOGIN_REQUIRED" }), L, false);
  assert.equal(expired.signIn, true);
  // A missing AWS configuration is not a sign-in: the command cannot help either, and nothing is offered here.
  assert.equal(identity.identityIssue(view({ sign_in: { reason: "AWS_CONFIG_NOT_MOUNTED" } }), L, true).signIn, undefined);
});

test("a team install offers no sign-in: it says how the server reaches AWS instead", () => {
  for (const extra of [{ sign_in: { reason: "NO_CACHED_SIGN_IN", requested_profile: "cremore" } },
    { sign_in: { reason: "SIGN_IN_EXPIRED" } }, { api: { state: "READY" }, hold: "AWS_LOGIN_REQUIRED" }]) {
    const issue = identity.identityIssue(view({ ...extra, sign_in_here: false }), L, true);
    assert.equal(issue.signIn, undefined);
    assert.equal(issue.code, undefined);
    assert.match(issue.fix, /서버.*실행 위치.*초기 설정|서버 역할.*기계 신원/);
  }
  // A single operator's install keeps both: the button and the command.
  assert.equal(identity.identityIssue(view({ sign_in: { reason: "SIGN_IN_EXPIRED" }, sign_in_here: true }), L, true).signIn, true);
});

test("each end of a sign-in from the console reads as what to do", () => {
  assert.match(identity.signInText("AWS_SSO_SESSION_REQUIRED: the profile has no sso-session", L), /aws configure sso/);
  assert.match(identity.signInText("SSO_CACHE_NOT_WRITABLE", L), /~\/\.aws\/sso\/cache/);
  assert.equal(identity.signInText("DENIED", L), "AWS 접근 포털에서 거절했습니다.");
  assert.match(identity.signInText("AWS_SIGN_IN_PRESENT: CreMore already has a working AWS sign-in", L), /여기서 바꾸지 않습니다/);
  assert.match(identity.signInText("AWS_SSO_LOGIN_SOLO_ONLY: a team install reaches AWS as the server", L), /팀 설치.*기계 신원/);
  assert.equal(identity.signInText("EXPIRED", L), "승인 시간이 지났습니다. 다시 로그인하세요.");
  assert.equal(identity.signInText("SOMETHING_ELSE", L), "로그인을 마치지 못했습니다.");
  assert.equal(identity.SSO_LOGIN_PATH, "aws/sso-login");
});
