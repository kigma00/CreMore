// The Microsoft connection in the console: catalog rules a target field turns on ("*"), the certificate CreMore
// made and how its renewal reads, what the connection's inventory counts, and the setup steps filled from the
// connection (app registration, certificate upload, Graph permissions, Azure roles, Azure DevOps). Synthetic
// catalog and connections only.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const guide = load("@/console/views/integrations/guide.tsx");
const copy = load("@/console/views/integrations/copy.ts");
const L = (ko, en) => ko;
const plain = value => JSON.parse(JSON.stringify(value));
const NOW = Date.parse("2026-09-29T03:00:00Z");
const CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmg\nAwIBAgIU\n-----END CERTIFICATE-----\n";

const MICROSOFT = {
  provider: "azure", label: "Microsoft", label_ko: "Microsoft", category: "cloud", editions: [{ id: "cloud", label: "c", label_ko: "c" }],
  target: [], auth_methods: [{ id: "certificate", label: "c", label_ko: "c", renewal: "AUTOMATIC", purposes: ["inventory"], generated: true }],
  purposes: {
    exposure: { scans: [{ id: "blobs", label: "Blob", label_ko: "Blob", when: { storage_account: ["*"] } },
      { id: "git", label: "Git", label_ko: "Git", when: { devops_project: ["*"] } }] },
    inventory: { types: [
      { id: "client_secret", label: "s", label_ko: "s", support: "YYYYNNNNP", reasons: {}, match: [{ provider: "azure_entra" }] },
      { id: "personal_access_token", label: "p", label_ko: "p", support: "YYYYYYYNY", reasons: {}, match: [{ provider: "azure_devops" }],
        when: { devops_organization: ["*"] } }] },
  },
};

function connection(changes = {}) {
  return {
    id: "c1", provider: "azure", edition: "cloud", name: "Microsoft · t", status: "ACTIVE", revision: 3,
    purposes: ["inventory", "exposure", "vault", "identity"], plans: { inventory: {} }, auth_method: "certificate", renewal: "AUTOMATIC",
    credential: { roles: ["credential"], reference: false }, children: [],
    checks: { results: {}, checked_at: "2026-09-29T02:00:00Z", requested_at: "2026-09-29T01:00:00Z", job_id: null, stale: false, error: null, renewal: null },
    target: { tenant: "11111111-2222-4333-8444-555555555555", subscription: "22222222-2222-4222-8222-222222222222", storage_account: "acmedata",
      key_vaults: ["acme-vault"], devops_organization: "acme", devops_project: "Payments", auth: { client_id: CLIENT },
      generated: { certificate: PEM, thumbprint: "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12", sha256: "00", not_before: "2026-09-29T00:00:00Z",
        not_after: "2027-03-28T03:00:00Z" } },
    ...changes,
  };
}

test("a target field named at all turns on what needs it", () => {
  assert.equal(model.applies({ when: { devops_organization: ["*"] } }, { devops_organization: "acme" }), true);
  assert.equal(model.applies({ when: { devops_organization: ["*"] } }, { devops_organization: "" }), false);
  assert.equal(model.applies({ when: { devops_organization: ["*"] } }, {}), false);
  assert.equal(model.applies({ when: { scope: ["group"] } }, { scope: "group" }), true);
  assert.deepEqual(plain(model.scansFor(MICROSOFT, "cloud", { storage_account: "acmedata" }).map(item => item.id)), ["blobs"]);
  assert.deepEqual(plain(model.scansFor(MICROSOFT, "cloud", { storage_account: "a", devops_project: "p" }).map(item => item.id)), ["blobs", "git"]);
});

test("a Microsoft connection counts the Azure DevOps PATs its organization lists", () => {
  const issued = provider => ({ issued: { provider, type: "x" } });
  const rows = [issued("azure_entra"), issued("azure_devops"), issued("github"), { issued: null }];
  assert.deepEqual([...model.inventoryProviders(MICROSOFT, connection())].sort(), ["azure", "azure_devops"]);
  assert.equal(model.inventoryCount(MICROSOFT, connection(), rows), 2);
  const withoutDevops = connection({ target: { ...connection().target, devops_organization: undefined } });
  assert.equal(model.inventoryCount(MICROSOFT, withoutDevops, rows), 1);
});

test("the certificate renews itself; an expired one or a failed renewal asks for a person", () => {
  assert.equal(model.generatedOf(connection()).thumbprint, "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12");
  assert.equal(model.generatedOf({ target: {} }), null);
  assert.equal(model.rowState(connection(), [], L, NOW).tone, "ok");
  const expired = model.rowState(connection(), [], L, Date.parse("2027-04-01T00:00:00Z"));
  assert.equal(expired.tone, "warn");
  assert.match(expired.note, /인증서가 만료됐습니다/);
  assert.equal(expired.fix, "reauth");
  const failed = connection({ checks: { ...connection().checks, renewal: { state: "FAILED", action: "renew", code: "AZURE_APPLICATION_READ_REQUIRED" } } });
  const state = model.rowState(failed, [], L, Date.parse("2027-02-01T03:00:00Z"));
  assert.equal(state.tone, "warn");
  assert.match(state.note, /자동 교체 실패 · 55일 뒤 만료 · 앱에 Application.Read.All이 없어/);
  // Removing the old certificate failing is not the connection's problem.
  const retire = connection({ checks: { ...connection().checks, renewal: { state: "FAILED", action: "retire", code: "AZURE_REMOVE_KEY_REFUSED" } } });
  assert.equal(model.rowState(retire, [], L, NOW).tone, "ok");
});

test("the setup steps start with the app registration, and fill the rest once the certificate exists", () => {
  const method = { id: "certificate", label: "c", label_ko: "c", renewal: "AUTOMATIC", purposes: ["inventory"], generated: true };
  const first = guide.guideSteps(MICROSOFT, method, null, {}, L);
  assert.deepEqual(plain(first.map(step => step.key)), ["app"]);
  assert.match(first[0].actions[1].text, /az ad app create --display-name "CreMore" --sign-in-audience AzureADMyOrg/);
  assert.match(first[0].actions[1].text, /az ad sp create --id "\$APP_ID"/);

  const steps = guide.guideSteps(MICROSOFT, method, connection(), {}, L);
  assert.deepEqual(plain(steps.map(step => step.key)), ["app", "certificate", "graph", "azure", "devops"]);
  const [download, upload] = steps[1].actions;
  assert.equal(download.download, "CreMore-AB12CD34.pem");
  assert.equal(decodeURIComponent(download.href.split(",")[1]), PEM);
  assert.equal(upload.text, `az ad app credential reset --id ${CLIENT} --append --cert "MIIBszCCAVmgAwIBAgIU"`);
  const graph = steps[2].actions[0].text;
  // Application.Read.All (renewal and the inventory), Organization.Read.All (inventory), User.Read.All (people).
  assert.match(graph, /--api 00000003-0000-0000-c000-000000000000 --api-permissions 9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role 498476ce-e0fe-48b0-b801-37ba7e2685c6=Role df021288-bdef-4463-88db-98f22de89214=Role/);
  assert.match(graph, /az ad app permission admin-consent --id aaaaaaaa/);
  const roles = steps[3].actions[0].text.split("\n");
  assert.deepEqual(roles, [
    `az role assignment create --assignee ${CLIENT} --role "Reader" --scope /subscriptions/22222222-2222-4222-8222-222222222222`,
    `az role assignment create --assignee ${CLIENT} --role "Storage Blob Data Reader" --scope "$(az storage account show --name acmedata --query id -o tsv)"`,
    `az role assignment create --assignee ${CLIENT} --role "Key Vault Reader" --scope "$(az keyvault show --name acme-vault --query id -o tsv)"`]);
  assert.deepEqual(plain(steps[4].actions.map(action => action.href)), ["https://dev.azure.com/acme/_settings/users", "https://dev.azure.com/acme/_settings/groups"]);
  // Only what the chosen features need: people alone ask for User.Read.All and the renewal's read.
  assert.deepEqual(plain(guide.graphRoles(["identity"])), ["Application.Read.All", "User.Read.All"]);
  const people = guide.guideSteps(MICROSOFT, method, connection({ purposes: ["identity"], target: { ...connection().target, devops_organization: "" } }), {}, L);
  assert.deepEqual(plain(people.map(step => step.key)), ["app", "certificate", "graph"]);
  // A certificate made again: the earlier one stays on the app registration until it is deleted there.
  const renewed = connection({ target: { ...connection().target, generated: { ...connection().target.generated, previous: { thumbprint: "0011223344556677889900112233445566778899" } } } });
  const retire = guide.guideSteps(MICROSOFT, method, renewed, {}, L).find(step => step.key === "retire");
  assert.match(retire.text, /이전 인증서\(지문 0011223344556677889900112233445566778899\)를 삭제합니다/);
  // The worker identity has no app registration to consent on: its Graph app roles go through Graph, its Azure
  // roles by object ID, and the machine identity step follows.
  const ambient = guide.guideSteps(MICROSOFT, { ...method, id: "workload_identity" }, connection(), { openMachine: () => {} }, L);
  assert.deepEqual(plain(ambient.map(step => step.key)), ["graph", "azure", "devops", "machine"]);
  const commands = ambient[0].actions[0].text.split("\n");
  assert.match(commands[1], /^GRAPH=\$\(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv\)$/);
  assert.equal(commands[2], 'az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" --body "{\\"principalId\\":\\"$MI\\",\\"resourceId\\":\\"$GRAPH\\",\\"appRoleId\\":\\"9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30\\"}"');
  assert.match(ambient[0].text, /권한 있는 역할 관리자/);
  // Azure roles are assigned by someone who holds roleAssignments/write on the scope, in a step of their own.
  const assignments = ambient[1].actions[0].text.split("\n");
  assert.match(assignments[0], /^MI="</);
  assert.ok(assignments.includes('az role assignment create --assignee-object-id "$MI" --assignee-principal-type ServicePrincipal --role "Reader" --scope /subscriptions/22222222-2222-4222-8222-222222222222'));
  assert.match(ambient[1].text, /사용자 액세스 관리자/);
  // Vault alone asks for no Graph app role, so only the Azure step remains.
  const vaultOnly = guide.guideSteps(MICROSOFT, { ...method, id: "workload_identity" }, connection({ purposes: ["vault"], target: { ...connection().target, devops_organization: "" } }), {}, L);
  assert.deepEqual(plain(vaultOnly.map(step => step.key)), ["azure"]);
  // People alone: the worker identity needs no Application.Read.All, since it renews nothing.
  assert.deepEqual(plain(guide.graphRoles(["identity"], {}, false)), ["User.Read.All"]);
  assert.deepEqual(plain(guide.guideSteps(MICROSOFT, { ...method, id: "workload_identity" }, null, {}, L)), []);
});

test("an onboarding's chosen targets each get their roles, from the form's comma-separated values", () => {
  const method = { id: "workload_identity", label: "w", label_ko: "w", renewal: "AUTOMATIC", purposes: ["inventory"] };
  const SUB = "22222222-2222-4222-8222-222222222222", OTHER = "33333333-3333-4333-8333-333333333333";
  const account = `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmekeys`;
  // How the wizard holds them: list fields joined with commas (model.valuesOf), the form's own key_vaults empty.
  const fields = [{ name: "storage_key_accounts", kind: "list" }, { name: "credential_sign_ins", kind: "bool" }];
  const plans = { inventory: model.valuesOf(fields, { storage_key_accounts: [account], credential_sign_ins: false }), vault: { read_values: true } };
  assert.equal(typeof plans.inventory.storage_key_accounts, "string");
  const roots = [{ purposes: ["inventory"], target: { tenant: "t", subscription: SUB } },
    { purposes: ["vault"], target: { tenant: "t", subscription: OTHER, key_vaults: ["vault-a"] } },
    { purposes: ["vault"], target: { tenant: "t", subscription: OTHER, key_vaults: ["vault-b"] } },
    { purposes: ["exposure"], target: { tenant: "t", subscription: OTHER, storage_account: "acmedata" } }];
  const conn = { target: { tenant: "t", key_vaults: "" }, children: [], purposes: ["inventory", "vault", "exposure"], roots };
  const steps = guide.guideSteps(MICROSOFT, method, conn, { plans }, L);
  const lines = steps.find(step => step.key === "azure").actions[0].text.split("\n");
  const who = '--assignee-object-id "$MI" --assignee-principal-type ServicePrincipal';
  assert.deepEqual(lines.slice(1), [
    `az role assignment create ${who} --role "Reader" --scope /subscriptions/${SUB}`,
    `az role assignment create ${who} --role "Key Vault Reader" --scope "$(az keyvault show --name vault-a --subscription ${OTHER} --query id -o tsv)"`,
    `az role assignment create ${who} --role "Key Vault Secrets User" --scope "$(az keyvault show --name vault-a --subscription ${OTHER} --query id -o tsv)"`,
    `az role assignment create ${who} --role "Key Vault Reader" --scope "$(az keyvault show --name vault-b --subscription ${OTHER} --query id -o tsv)"`,
    `az role assignment create ${who} --role "Key Vault Secrets User" --scope "$(az keyvault show --name vault-b --subscription ${OTHER} --query id -o tsv)"`,
    `az role assignment create ${who} --role "Storage Blob Data Reader" --scope "$(az storage account show --name acmedata --subscription ${OTHER} --query id -o tsv)"`,
    `az role assignment create ${who} --role "Reader and Data Access" --scope ${account}`]);
  assert.deepEqual(plain(model.listValue("a, b c")), ["a", "b", "c"]);
  assert.deepEqual(plain(model.listValue(["a"])), ["a"]);
  assert.deepEqual(plain(model.listValue(undefined)), []);
});

test("the options and the plan add what they read: sign-in and audit logs, key fingerprints, Key Vault values", () => {
  const method = { id: "certificate", label: "c", label_ko: "c", renewal: "AUTOMATIC", purposes: ["inventory"], generated: true };
  const account = "/subscriptions/22222222-2222-4222-8222-222222222222/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmekeys";
  const plans = { inventory: { credential_sign_ins: true, storage_key_accounts: [account] }, vault: { read_values: true } };
  const steps = guide.guideSteps(MICROSOFT, method, connection(), { plans }, L);
  assert.match(steps[2].actions[0].text, /df021288-bdef-4463-88db-98f22de89214=Role b0afded3-3588-46d8-8b3d-9842eff778da=Role/);
  assert.match(steps[2].text, /Microsoft Entra ID P1 또는 P2/);
  const roles = steps[3].actions[0].text.split("\n");
  assert.ok(roles.includes(`az role assignment create --assignee ${CLIENT} --role "Reader and Data Access" --scope ${account}`));
  assert.ok(roles.includes(`az role assignment create --assignee ${CLIENT} --role "Key Vault Secrets User" --scope "$(az keyvault show --name acme-vault --query id -o tsv)"`));
  // The directory audit alone asks for the log permission without the license note.
  const audits = guide.guideSteps(MICROSOFT, method, connection(), { plans: { inventory: { directory_audits: true } } }, L);
  assert.match(audits[2].actions[0].text, /b0afded3-3588-46d8-8b3d-9842eff778da=Role/);
  assert.doesNotMatch(audits[2].text, /P1/);
  // App permissions read the apps' Entra roles (RoleManagement.Read.Directory); Azure roles are read at the tenant root
  // management group with a custom role that only reads role assignments and definitions.
  const apps = guide.guideSteps(MICROSOFT, method, connection(), { plans: { inventory: { app_permissions: true } } }, L);
  assert.match(apps[2].actions[0].text, /483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role/);
  assert.doesNotMatch(apps[3].actions[0].text, /managementGroups/);
  const group = "/providers/Microsoft.Management/managementGroups/11111111-2222-4333-8444-555555555555";
  const azure = guide.guideSteps(MICROSOFT, method, connection(), { plans: { inventory: { app_azure_roles: true } } }, L);
  assert.doesNotMatch(azure[2].actions[0].text, /483bed4a/);
  const lines = azure[3].actions[0].text.split("\n");
  const definition = JSON.parse(lines.find(line => line.startsWith("az role definition create")).match(/'(.*)'$/)[1]);
  assert.deepEqual(definition.Actions, ["Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleDefinitions/read"]);
  assert.deepEqual(definition.AssignableScopes, [group]);
  assert.ok(lines.includes(`az role assignment create --assignee ${CLIENT} --role "CreMore Role Assignment Reader" --scope ${group}`));
  assert.ok(!lines.some(line => line.includes(`--role "Reader" --scope ${group}`)));
  assert.match(azure[3].text, /테넌트 루트 관리 그룹/);
  // The worker's own identity gets the same custom role by object ID.
  const ambient = guide.guideSteps(MICROSOFT, { ...method, id: "workload_identity" }, connection(), { plans: { inventory: { app_azure_roles: true } } }, L);
  assert.ok(ambient.find(step => step.key === "azure").actions[0].text.split("\n").includes(
    `az role assignment create --assignee-object-id "$MI" --assignee-principal-type ServicePrincipal --role "CreMore Role Assignment Reader" --scope ${group}`));
});

test("the certificate method has its own name and hint", () => {
  assert.equal(copy.methodShort({ id: "certificate", label: "", label_ko: "" }, L), "앱 인증서");
  assert.match(copy.methodHint("azure", { id: "certificate", renewal: "AUTOMATIC" }, L), /만료 전에 CreMore가 스스로 새 인증서로 바꿉니다/);
  assert.match(model.onboardingText("AZURE_EXPOSURE_TARGET_REQUIRED", [], L), /스토리지 계정이나 Azure DevOps 프로젝트/);
  assert.equal(model.detailText("AZURE_CERTIFICATE_NOT_REGISTERED", L), "앱 등록에 이 인증서가 없음");
});
