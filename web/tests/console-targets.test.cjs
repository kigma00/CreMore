// The console's scan targets window and the AWS identity it shares with every other provider's sign-in:
// what choosing a listed resource selects, how far a choice was narrowed, what the server would refuse, the
// body a save sends, and when testing an AWS connection approves CreMore's identity. Synthetic rows only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

const model = load("@/console/views/integrations/targets-model.ts");
const identity = load("@/console/views/integrations/aws-identity.tsx");
const guide = load("@/console/views/integrations/guide.tsx");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));

const item = (changes = {}) => ({
  id: "r1", provider_resource_id: "app-config-prod", resource_type: "S3_BUCKET", display_name: "app-config-prod",
  canonical_reference: "arn:aws:s3:::app-config-prod", provider_instance_id: "aws", account_id: "123456789012", region: "ap-northeast-2",
  visibility: "UNKNOWN", list_visibility: "VISIBLE", content_readiness: "NOT_PROBED", ...changes,
});

test("choosing a resource selects what it holds: every object, the default branch, the page alone, no rows", () => {
  assert.equal(model.defaultRoot(item()).all_current_objects, true);
  const repo = model.defaultRoot(item({ resource_type: "GITLAB_REPOSITORY", default_branch: "main" }));
  assert.equal(repo.ref, "refs/heads/main");
  assert.equal(repo.all_current_objects, false);
  assert.equal(model.defaultRoot(item({ resource_type: "NOTION_PAGE" })).page_mode, "PAGE_ONLY");
  const rows = model.defaultRoot(item({ resource_type: "NOTION_DATA_SOURCE" }));
  assert.equal(rows.page_mode, "DATA_SOURCE_SELECTED_PAGES");
  assert.deepEqual(plain(rows.descendant_ids), []);
  assert.equal(model.defaultRoot(item({ resource_type: "CONFLUENCE_PAGE" })).page_mode, undefined);
});

test("only a listed, readable resource of a known kind can be chosen", () => {
  assert.equal(model.pickable(item()).ok, true);
  assert.deepEqual(plain(model.pickable(item({ list_visibility: "DENIED", reason_code: "HTTP_403" }))), { ok: false, reason: "HTTP_403" });
  assert.equal(model.pickable(item({ content_readiness: "INSUFFICIENT_PERMISSION" })).ok, false);
  assert.equal(model.pickable(item({ resource_type: "SOMETHING_ELSE" })).ok, false);
});

test("the server's refusals are caught before a save", () => {
  const bucket = model.defaultRoot(item());
  assert.equal(model.rootProblem(bucket, "S3_BUCKET"), null);
  assert.equal(model.rootProblem({ ...bucket, all_current_objects: false }, "S3_BUCKET"), "BUCKET_OBJECT_SELECTION_REQUIRED");
  assert.equal(model.rootProblem({ ...bucket, all_current_objects: false, prefixes: ["config/"] }, "S3_BUCKET"), null);
  assert.equal(model.rootProblem({ ...bucket, all_current_objects: false }, "AZURE_BLOB_CONTAINER"), "BUCKET_OBJECT_SELECTION_REQUIRED");
  const rows = model.defaultRoot(item({ resource_type: "NOTION_DATA_SOURCE" }));
  assert.equal(model.rootProblem(rows, "NOTION_DATA_SOURCE"), "DATA_SOURCE_ROWS_REQUIRED");
  assert.equal(model.rootProblem({ ...rows, descendant_ids: ["row-1"] }, "NOTION_DATA_SOURCE"), null);
  assert.equal(model.rootProblem({ ...rows, descendant_ids: ["row-1"], page_mode: "PAGE_ONLY" }, "NOTION_DATA_SOURCE"), "DATA_SOURCE_PAGE_MODE_INVALID");
  assert.equal(model.rootProblem({ ...bucket, include_future_descendants: true }, "S3_BUCKET"), "FUTURE_DESCENDANTS_NOT_SUPPORTED");
});

test("a choice says how far it reaches, and whether it was narrowed", () => {
  const bucket = model.defaultRoot(item());
  assert.equal(model.reachText(bucket, "S3_BUCKET", L), "모든 객체");
  assert.equal(model.narrowed(bucket, "S3_BUCKET"), false);
  const narrowed = { ...bucket, all_current_objects: false, prefixes: ["exports/", "config/"], excluded_prefixes: ["exports/tmp/"] };
  assert.equal(model.reachText(narrowed, "S3_BUCKET", L), "접두어 2개 · 제외 1개");
  assert.equal(model.narrowed(narrowed, "S3_BUCKET"), true);
  const repo = { ...model.defaultRoot(item({ resource_type: "GITHUB_REPOSITORY", default_branch: "main" })), paths: ["deploy/"] };
  assert.equal(model.reachText(repo, "GITHUB_REPOSITORY", L), "main · 경로 1개");
  assert.equal(model.reachText({ ...model.defaultRoot(item({ resource_type: "NOTION_PAGE" })), page_mode: "PAGE_WITH_DESCENDANTS" }, "NOTION_PAGE", L), "이 페이지만");
  assert.equal(model.reachText(model.defaultRoot(item({ resource_type: "CONFLUENCE_PAGE" })), "CONFLUENCE_PAGE", L), "본문·첨부");
  assert.equal(model.reachText(model.defaultRoot(item({ resource_type: "WEBSITE" })), "WEBSITE", L), "시작 페이지·스크립트·소스맵");
});

test("Notion page reach reflects explicit descendants and preserves saved scope", () => {
  const page = model.defaultRoot(item({ resource_type: "NOTION_PAGE" }));
  for (const say of [L, (ko, en) => en]) {
    const only = model.reachText(page, "NOTION_PAGE", say);
    const empty = { ...page, page_mode: "PAGE_WITH_DESCENDANTS" };
    assert.equal(model.reachText(empty, "NOTION_PAGE", say), only);
    assert.equal(model.narrowed(empty, "NOTION_PAGE"), true); // The review includes the corrected reach.
    assert.equal(model.reachText({ ...page, descendant_ids: ["child"] }, "NOTION_PAGE", say), only);
    const saved = { ...empty, descendant_ids: ["child"] };
    assert.notEqual(model.reachText(saved, "NOTION_PAGE", say), only);
    const body = model.profileBody({ roots: [saved], snapshot: "snap", schedule: 0, reason: "keep", name: "scope" });
    assert.deepEqual(plain(body.selected_roots[0]), plain(saved));
    assert.equal(model.rootProblem(saved, "NOTION_PAGE"), null);
  }
});

test("Notion pages offer no unsupported subpage control while other narrowing remains", () => {
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { TargetRow, Narrowing } = load("@/console/views/integrations/targets.tsx", { extraExports: "\nexport { TargetRow, Narrowing };" });
  const target = { kind: "source", id: "source", sourceType: "notion", name: "Notion" };
  for (const resource_type of ["NOTION_PAGE", "CONFLUENCE_PAGE"]) {
    const resource = item({ resource_type });
    const root = model.defaultRoot(resource);
    const html = renderToStaticMarkup(React.createElement(TargetRow, {
      item: resource, root, open: false, target, onChoose() {}, onOpen() {}, onRoot() {},
    }));
    assert.doesNotMatch(html, /aria-expanded/);
    assert.equal(renderToStaticMarkup(React.createElement(Narrowing, { item: resource, root, target, onRoot() {} })), "");
  }
  const bucket = item();
  assert.match(renderToStaticMarkup(React.createElement(TargetRow, {
    item: bucket, root: model.defaultRoot(bucket), open: false, target, onChoose() {}, onOpen() {}, onRoot() {},
  })), /aria-expanded="false"/);
});

test("typed prefixes and paths preserve literal spaces and commas", () => {
  assert.deepEqual(plain(model.lines("approved/ \n private/\n \ncomma,name/\n\napproved/ ")), ["approved/ ", " private/", " ", "comma,name/"]);
  assert.deepEqual(plain(model.lines("first/\r\n second/\r\n")), ["first/", " second/"]);
  const root = { ...model.defaultRoot(item()), all_current_objects: false, prefixes: model.lines(" "), excluded_prefixes: model.lines(" private/\ncommas,stay/") };
  const body = model.profileBody({ roots: [root], snapshot: "snap", schedule: 0, reason: "literal prefixes", name: "scope" });
  assert.deepEqual(plain(body.selected_roots[0].prefixes), [" "]);
  assert.deepEqual(plain(body.selected_roots[0].excluded_prefixes), [" private/", "commas,stay/"]);
  assert.equal(body.selected_roots[0].all_current_objects, false);
  const empty = { ...root, prefixes: model.lines("\n\n") };
  assert.equal(model.rootProblem(empty, "S3_BUCKET"), "BUCKET_OBJECT_SELECTION_REQUIRED");
  assert.equal(model.profileBody({ roots: [empty], snapshot: "snap", schedule: 0, reason: "", name: "scope" }).selected_roots[0].all_current_objects, false);
});

test("a save names what changed against the saved choice", () => {
  const a = model.defaultRoot(item({ id: "a" }));
  const b = model.defaultRoot(item({ id: "b" }));
  const current = new Map([["a", { ...a, prefixes: ["x/"], all_current_objects: false }], ["c", model.defaultRoot(item({ id: "c" }))]]);
  assert.deepEqual(plain(model.changes([a, b], current)), { added: 1, removed: 1, changed: 1 });
  assert.deepEqual(plain(model.changes([a], new Map([["a", { ...a }]]))), { added: 0, removed: 0, changed: 0 });
});

test("the saved body carries exact ids, the snapshot seen, the schedule, and drops exclusions chosen again", () => {
  const root = model.defaultRoot(item({ id: "a" }));
  const saved = { id: "p1", version: 3, name: "계정 1 · 검사 대상", state: "READY", selected_roots: [], excluded_ids: ["a", "z"],
    budgets: { bytes: 10, requests: 20, seconds: 30 }, schedule_minutes: 0, event_mode: "DISABLED", catalog_snapshot_id: "old" };
  const body = model.profileBody({ saved, roots: [root], snapshot: "snap-2", schedule: 1440, reason: "이유", name: "무시됨" });
  assert.equal(body.expected_version, 3);
  assert.equal(body.name, "계정 1 · 검사 대상");
  assert.equal(body.catalog_snapshot_id, "snap-2");
  assert.equal(body.schedule_minutes, 1440);
  assert.deepEqual(plain(body.excluded_ids), ["z"]);
  assert.deepEqual(plain(body.budgets), { bytes: 10, requests: 20, seconds: 30 });
  assert.equal(body.selected_roots[0].resource_id, "a");
  const fresh = model.profileBody({ roots: [root], snapshot: "snap", schedule: 0, reason: "r", name: "새 이름" });
  assert.equal(fresh.expected_version, 0);
  assert.equal(fresh.name, "새 이름");
  // Events are asked for only when the admin says so; otherwise the saved choice stands.
  assert.equal(body.event_mode, "DISABLED");
  assert.equal(fresh.event_mode, "DISABLED");
  assert.equal(model.profileBody({ saved, roots: [root], snapshot: "s", schedule: 0, reason: "r", name: "n", events: true }).event_mode, "ENABLED");
  assert.equal(model.profileBody({ saved: { ...saved, event_mode: "ENABLED" }, roots: [root], snapshot: "s", schedule: 0, reason: "r", name: "n" }).event_mode, "ENABLED");
  assert.equal(model.profileBody({ saved: { ...saved, event_mode: "ENABLED" }, roots: [root], snapshot: "s", schedule: 0, reason: "r", name: "n", events: false }).event_mode, "DISABLED");
});

test("an untouched choice for every place never rewrites another place's saved value", () => {
  // The review shows what every saved place shares, nothing when they differ.
  assert.equal(model.sharedChoice([true, true]), true);
  assert.equal(model.sharedChoice([1440, 1440]), 1440);
  assert.equal(model.sharedChoice([true, false]), null);
  assert.equal(model.sharedChoice([]), null);
  // Untouched (null): each place keeps its own; a place saved for the first time takes what is shown.
  assert.equal(model.placeChoice(null, true, false), true);
  assert.equal(model.placeChoice(null, false, true), false);
  assert.equal(model.placeChoice(null, undefined, true), true);
  assert.equal(model.placeChoice(null, 360, 0), 360);
  // Touched: every place takes the admin's choice, whatever it saved.
  assert.equal(model.placeChoice(false, true, true), false);
  assert.equal(model.placeChoice(0, 1440, 1440), 0);
  assert.equal(model.scheduleText(0, L), "직접 실행할 때만");
  assert.equal(model.scheduleText(1440, L), "매일");
  assert.equal(model.scheduleText(2880, L), "2일마다");
  const en = (ko, english) => english;
  assert.deepEqual([60, 120, 30].map(minutes => model.scheduleText(minutes, en)), ["Every hour", "Every 2 hours", "Every 30 minutes"]);
});

test("a full scan runs 1, 2, 3, 4, 6, 8, 12 or 24 times a day, off, or as the installation default", () => {
  const en = (ko, english) => english;
  // The same closed choices the server accepts (cremore/scanning/trigger_settings.py FULL_SCAN_CHOICES).
  assert.deepEqual([...model.FULL_SCHEDULES].sort((a, b) => a - b), [0, 60, 120, 180, 240, 360, 480, 720, 1440]);
  assert.deepEqual([...model.FULL_SCHEDULES].map(minutes => model.fullScanText(minutes, L)),
    ["하루 1회", "하루 2회", "하루 3회", "하루 4회", "하루 6회", "하루 8회", "하루 12회", "하루 24회", "끄기"]);
  assert.equal(model.fullScanText(1440, en), "Once a day");
  assert.equal(model.fullScanText(90, en), "16 times a day");  // a saved cadence outside the choices reads as it is
  assert.equal(model.fullScanText(100, en), "Every 100 minutes");
  // The installation default is null on the scope; the choice says what it means now, on the display zone's clock.
  assert.equal(model.INSTALLATION_DEFAULT, -2);
  // A scope's full scan starts at its own fixed time within min(4 hours, half the cadence) of the start minute.
  assert.equal(model.defaultText(1440, 1020, "Asia/Seoul", L), "설치 기본값 · 하루 1회, 02:00 KST부터 4시간 안");
  assert.equal(model.defaultText(720, 1020, "UTC", en), "Installation default · 2 times a day from 17:00 UTC, within 4 hours");
  assert.equal(model.defaultText(360, 1020, "UTC", en), "Installation default · 4 times a day from 17:00 UTC, within 3 hours");
  assert.equal(model.defaultText(120, 1020, "UTC", en), "Installation default · 12 times a day from 17:00 UTC, within 1 hour");
  assert.equal(model.defaultText(60, 1020, "Asia/Seoul", L), "설치 기본값 · 하루 24회, 02:00 KST부터 30분 안");
  assert.equal(model.defaultText(0, 1020, "Asia/Seoul", en), "Installation default · Off");
  assert.equal(model.defaultText(undefined, undefined, "Asia/Seoul", en), "Installation default");
  assert.equal(model.startText(0, "Asia/Seoul", L), "09:00 KST");
  assert.equal(model.shiftMinute(1020, 540), 120);
  assert.equal(model.shiftMinute(120, -540), 1020);
  // A save of "installation default" sends null, never a number.
  const fresh = model.profileBody({ roots: [model.defaultRoot(item())], snapshot: "s", schedule: 0, fullScan: null, reason: "r", name: "n" });
  assert.equal(fresh.full_scan_minutes, null);
});

test("every sentence beside a per-scope full-scan picker gives the spread window with its half-interval limit", () => {
  // A 1-6 hour cadence spreads over half its interval, not 4 hours (cremore/scanning/triggers.py full_scan_offset).
  for (const path of ["@/console/views/integrations/targets.tsx", "@/console/views/integrations/auth-first.tsx"]) {
    const screen = source(path);
    assert.match(screen, /시작 시각부터 최대 4시간 뒤\(주기가 8시간보다 짧으면 주기의 절반\) 사이에 시작합니다/, path);
    assert.match(screen, /up to 4 hours later \(half the interval when it is shorter than 8 hours\)/, path);
  }
});

test("the list shows readiness and facts without repeating the account a tab already names", () => {
  assert.equal(model.readiness(item({ content_readiness: "READY" }), L).tone, "ok");
  assert.equal(model.readiness(item({ list_visibility: "DENIED" }), L).text, "목록 권한 없음");
  assert.deepEqual(plain(model.facts(item(), L)), ["계정 123456789012", "ap-northeast-2"]);
  assert.deepEqual(plain(model.facts(item(), L, true)), ["ap-northeast-2"]);
  assert.deepEqual(plain(model.facts(item({ resource_type: "GITHUB_REPOSITORY", account_id: undefined, region: undefined, visibility: "PRIVATE", default_branch: "main", archived: true }), L)),
    ["비공개", "main", "보관됨"]);
});

const view = (changes = {}) => ({
  api: { state: "READY", kind: "IDENTITY_CENTER", account_id: "111111111111", permission_set: "SecurityAudit", requires: null },
  worker: { state: "READY", kind: "IDENTITY_CENTER", account_id: "111111111111" }, sign_in: null, worker_stale: false, same_identity: true,
  approvable: null, approved: null, hold: null, policy: { Version: "2012-10-17" }, permission_set_policy: { Version: "2012-10-17" }, ...changes,
});

test("testing an AWS connection approves the identity only when none is approved or it changed", () => {
  assert.equal(identity.needsApproval(view()), true);
  const approved = { kind: "IDENTITY_CENTER", account_id: "111111111111", permission_set: "SecurityAudit" };
  assert.equal(identity.needsApproval(view({ approved })), false);
  assert.equal(identity.needsApproval(view({ approved, hold: "AWS_SCANNER_IDENTITY_CHANGED" })), true);
  assert.equal(identity.identityText(view(), L), "IAM Identity Center · SecurityAudit · 111111111111");
  assert.equal(identity.identityText(view({ api: { state: "NO_CREDENTIALS" } }), L), null);
});

test("what stops the identity reads as one result line, with the fix", () => {
  assert.equal(identity.identityIssue(view(), L, true), null);
  assert.match(identity.identityIssue(view({ same_identity: false }), L, true).text, /서로 다른 AWS 신원/);
  assert.match(identity.identityIssue(view({ worker: null }), L, true).text, /워커가 AWS 신원을 보고하지/);
  assert.match(identity.identityIssue(view({ approvable: "ROOT_CREDENTIALS_REFUSED" }), L, true).text, /루트 사용자/);
  // A role ARN still to be typed is an input, not a refusal.
  assert.equal(identity.identityIssue(view({ approvable: "ROLE_ARN_REQUIRED", api: { state: "READY", requires: "ROLE_ARN" } }), L, true), null);
  const expired = identity.identityIssue(view({ sign_in: { reason: "SIGN_IN_EXPIRED", requested_profile: "ops" } }), L, false);
  assert.equal(expired.code, "aws sso login --use-device-code --profile ops");
  // An approved identity in use is not re-checked for approval.
  assert.equal(identity.identityIssue(view({ same_identity: false }), L, false), null);
});

test("AWS setup steps are the shared kind: a policy to copy and, for member roles, one role per account", () => {
  const roleSteps = guide.guideSteps({ provider: "aws" }, { id: "role" }, null, { aws: view() }, L);
  assert.deepEqual(plain(roleSteps.map(step => step.key)), ["hub", "organization-list", "roles"]);
  assert.equal(roleSteps[0].actions[0].kind, "copy");
  // The hub policy names the registered accounts; the ones being connected join them, an organization covers them.
  const hub = account => ({ Version: "2012-10-17", Statement: [{ Action: "sts:AssumeRole", Resource: "arn:aws:iam::*:role/R",
    ...(account ? { Condition: { StringEquals: { [account]: account === "aws:ResourceOrgID" ? ["o-abc123"] : ["222222222222"] } } } : {}) }] });
  const draft = ["111111111111", "222222222222"];
  assert.deepEqual(plain(guide.withAccounts(hub("aws:ResourceAccount"), draft).Statement[0].Condition),
    { StringEquals: { "aws:ResourceAccount": ["111111111111", "222222222222"] } });
  assert.deepEqual(plain(guide.withAccounts(hub(null), ["333333333333"]).Statement[0].Condition),
    { StringEquals: { "aws:ResourceAccount": ["333333333333"] } });
  assert.deepEqual(plain(guide.withAccounts(hub("aws:ResourceOrgID"), draft)), plain(hub("aws:ResourceOrgID")));
  assert.deepEqual(plain(guide.withAccounts(hub(null), [])), plain(hub(null)));
  // Listing the organization's accounts, and the OU structure each sweep reads with the same identity.
  assert.deepEqual(JSON.parse(roleSteps[1].actions[0].text).Statement[0].Action,
    ["organizations:ListAccounts", "organizations:ListAccountsForParent", "organizations:ListOrganizationalUnitsForParent",
      "organizations:ListRoots", "organizations:DescribeOrganization"]);
  assert.equal(roleSteps[2].actions[0].href, "/api/backend/aws/onboarding/template");
  const sso = guide.guideSteps({ provider: "aws" }, { id: "sso" }, null, { aws: view() }, L);
  assert.deepEqual(plain(sso.map(step => step.key)), ["read"]);
  assert.deepEqual(plain(guide.guideSteps({ provider: "aws" }, { id: "customer_cli" }, null, { aws: view() }, L)), []);
  assert.deepEqual(plain(guide.guideSteps({ provider: "gitlab" }, { id: "token" }, null, {}, L)), []);
});

test("the role creation command also makes the value-reader role with the vault plan's targets", () => {
  const A = "111111111111", B = "222222222222";
  const vault = { regions: "us-east-1, eu-west-1", ssm_prefixes: "/prod/", value_reader: true, value_reader_role: "VaultReader",
    secret_arns: `arn:aws:secretsmanager:us-east-1:${A}:secret:prod/db-AbCdEf, arn:aws:secretsmanager:us-east-1:${B}:secret:prod/db-GhIjKl`,
    kms_key_arns: `arn:aws:kms:us-east-1:${A}:key/1234abcd-12ab-34cd-56ef-1234567890ab, arn:aws:kms:us-east-1:${B}:key/5678abcd-12ab-34cd-56ef-1234567890ab` };
  assert.deepEqual(plain(guide.valueReaderParameters({ ...vault, value_reader: false }, "aws", A)), {});
  assert.deepEqual(plain(guide.valueReaderParameters(vault, "aws", A)), {
    EnableVaultValueRead: "true", VaultValueReaderRoleName: "VaultReader",
    VaultSecretArns: `arn:aws:secretsmanager:us-east-1:${A}:secret:prod/db-AbCdEf`,
    VaultParameterPathArns: [`arn:aws:ssm:us-east-1:${A}:parameter/prod`, `arn:aws:ssm:us-east-1:${A}:parameter/prod/*`,
      `arn:aws:ssm:eu-west-1:${A}:parameter/prod`, `arn:aws:ssm:eu-west-1:${A}:parameter/prod/*`].join(","),
    VaultKmsKeyArns: `arn:aws:kms:us-east-1:${A}:key/1234abcd-12ab-34cd-56ef-1234567890ab` });
  // What the server would refuse, or would break the command's quoting, is never put in it: the same secret ARN rule
  // (a known partition, the six-character suffix), and each account's own secrets and keys only.
  const odd = guide.valueReaderParameters({ ...vault, value_reader_role: "it's", secret_arns: [`arn:aws:secretsmanager:us-east-1:${A}:secret:*`,
    `arn:aws:secretsmanager:us-east-1:${A}:secret:prod/db`, `arn:aws-iso:secretsmanager:us-iso-east-1:${A}:secret:prod/db-AbCdEf`] }, "aws", A);
  assert.equal(odd.VaultValueReaderRoleName, "CredentialVaultValueReaderRole");
  assert.equal(odd.VaultSecretArns, "");
  assert.equal(guide.valueReaderParameters(vault, "aws", B).VaultKmsKeyArns, `arn:aws:kms:us-east-1:${B}:key/5678abcd-12ab-34cd-56ef-1234567890ab`);
  // A saved plan holds real lists and booleans; the reach screen passes it as saved.
  assert.equal(guide.valueReaderParameters({ value_reader: true, regions: ["us-east-1"], ssm_prefixes: ["/prod/"],
    secret_arns: [`arn:aws:secretsmanager:us-east-1:${A}:secret:prod/db-AbCdEf`] }, "aws", A).VaultParameterPathArns,
    `arn:aws:ssm:us-east-1:${A}:parameter/prod,arn:aws:ssm:us-east-1:${A}:parameter/prod/*`);
  const role = (account_id, existing) => ({ account_id, role_arn: `arn:aws-us-gov:iam::${account_id}:role/CredentialExposureScannerRole`, existing,
    command: "aws cloudformation deploy --parameter-overrides 'ExternalId=e'", parameters: { ExternalId: "e" } });
  const conn = { target: { generated: { aws_roles: [role(A, false), role(B, true)] } }, children: [], purposes: ["vault"] };
  const steps = guide.guideSteps({ provider: "aws" }, { id: "role" }, conn, { aws: view(), plans: { vault } }, L);
  const fresh = steps.find(step => step.key === `draft-role:${A}`);
  const command = fresh.actions.find(action => action.label === "역할 만들기 명령 복사").text;
  assert.ok(command.startsWith("aws cloudformation deploy --parameter-overrides 'ExternalId=e' 'EnableVaultValueRead=true' 'VaultValueReaderRoleName=VaultReader'"));
  assert.match(command, new RegExp(`'VaultParameterPathArns=arn:aws-us-gov:ssm:us-east-1:${A}:parameter/prod,`));
  assert.match(fresh.text, /값 읽기 역할\(VaultReader\)/);
  // A role that already exists shows its parameters, with the reader's, to update the stack.
  const existing = steps.find(step => step.key === `draft-role:${B}`);
  assert.deepEqual(plain(existing.actions.map(action => action.label)), ["역할 설정값 복사"]);
  assert.equal(JSON.parse(existing.actions[0].text).VaultSecretArns, `arn:aws:secretsmanager:us-east-1:${B}:secret:prod/db-GhIjKl`);
  // Without the option the command is what the server built.
  const plainSteps = guide.guideSteps({ provider: "aws" }, { id: "role" }, conn, { aws: view(), plans: { vault: { ...vault, value_reader: false } } }, L);
  assert.equal(plainSteps.find(step => step.key === `draft-role:${A}`).actions[1].text, role(A, false).command);
});

test("AWS role lookup advice names only the caller's role and never guesses its path", () => {
  const api = { state: "READY", requires: "ROLE_ARN", caller_arn: "arn:aws:sts::111111111111:assumed-role/Scanner/server" };
  const steps = guide.guideSteps({ provider: "aws" }, { id: "role" }, null, { aws: view({ api }) }, L);
  assert.equal(steps[0].key, "identity-lookup");
  assert.deepEqual(JSON.parse(steps[0].actions[0].text), { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "iam:GetRole",
    Resource: ["arn:aws:iam::111111111111:role/Scanner", "arn:aws:iam::111111111111:role/*/Scanner"] }] });
  for (const caller_arn of ["arn:aws:iam::111111111111:user/Scanner", "arn:aws:sts::111111111111:assumed-role/*/session", "invalid"]) {
    assert.equal(guide.guideSteps({ provider: "aws" }, { id: "role" }, null, { aws: view({ api: { ...api, caller_arn } }) }, L)
      .some(step => step.key === "identity-lookup"), false);
  }
  const missing = view({ api: { state: "NO_CREDENTIALS" }, sign_in_here: false, sign_in: { reason: "AWS_CONFIG_NOT_MOUNTED" } });
  assert.deepEqual(plain(guide.guideSteps({ provider: "aws" }, { id: "role" }, null, { aws: missing, openMachine() {} }, L).map(s => s.key)), ["aws-bootstrap"]);
  assert.match(identity.identityIssue(missing, L, true).text, /서버의 AWS 신원 설정/);
});
