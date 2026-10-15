// Offline render checks only: no Kubernetes context or provider calls.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const chart = path.resolve(__dirname, "..");
const image = "alpine/helm:3.17.2@sha256:b80eb190fca14707e94a5090235a3f1bf2f206f26761f2890d16a1e570386236";
const nativeHelm = process.env.CREMORE_HELM_BINARY;
function success(result) {
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  return result.stdout;
}
if (nativeHelm) assert.match(success(spawnSync(nativeHelm, ["version", "--short"], { encoding: "utf8", timeout: 10000 })), /^v3\.17\.2(?:\+|\s|$)/);
function helm(values = [], jsonValues = []) {
  const args = nativeHelm ? ["template", "chart-check", chart] : ["run", "--rm", "--network", "none", "--pull", "never", "-v", `${chart}:/chart:ro`, image, "template", "chart-check", "/chart"];
  for (const value of ["isolation.enabled=true", "networkPolicy.databaseCIDR=10.20.0.2/32", ...values]) {
    args.push(/=(?:true|false)$/.test(value) ? "--set" : "--set-string", value);
  }
  for (const value of jsonValues) args.push("--set-json", value);
  return spawnSync(nativeHelm || "docker", args, { encoding: "utf8", timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
}
function document(output, kind, component) {
  const result = output.split(/^---\s*$/m).find(value => value.includes(`kind: ${kind}\n`) && new RegExp(`^  name: .*-${component}$`, "m").test(value));
  assert.ok(result, `${kind} ${component} rendered`);
  return result;
}
const deployment = (output, component) => document(output, "Deployment", component);
const policy = (output, component) => document(output, "NetworkPolicy", component);
const envValue = (doc, name) => {
  const match = doc.match(new RegExp(`name: ${name}, value: ("(?:\\\\.|[^"\\\\])*")`));
  assert.ok(match, `${name} has a quoted value`);
  return JSON.parse(match[1]);
};
function denied(values, message, json = []) {
  const result = helm(values, json);
  assert.equal(result.error, undefined, result.error?.message);
  assert.notEqual(result.status, 0, "unsafe isolation configuration must fail rendering");
  assert.match(result.stderr + result.stdout, message);
}
let defaultOutput;
function defaults() { return defaultOutput ||= success(helm()); }

test("isolated workloads receive only their role keys and database identity", () => {
  const output = defaults();
  for (const [component, role, db] of [["api", "control", "api"], ["worker", "collector", "collector"], ["remediator", "remediator", "remediator"], ["control", "control", "control"]]) {
    const doc = deployment(output, component);
    assert.equal(envValue(doc, "WORKER_EXECUTION_ROLE"), role);
    assert.match(doc, new RegExp(`name: DATABASE_URL\\s+valueFrom: \\{ secretKeyRef: \\{ name: cremore-db-${db}, key: url`));
    assert.match(doc, /SEALING_PUBLIC_KEYS_FILE/);
    assert.match(doc, /REMEDIATION_APPROVAL_PUBLIC_KEY_FILE/);
    assert.match(doc, /runAsNonRoot: true/);
    assert.match(doc, /readOnlyRootFilesystem: true/);
    assert.match(doc, /allowPrivilegeEscalation: false/);
    assert.match(doc, /automountServiceAccountToken: false/);
    assert.match(doc, /capabilities: \{ drop: \["ALL"\] \}/);
    if (["worker", "remediator"].includes(component)) {
      assert.match(doc, /SEALING_PRIVATE_KEYS_FILE/);
      assert.match(doc, new RegExp(`secretName: cremore-${role}-keys`));
      assert.doesNotMatch(doc, /CONTROL_SEALING_KEY|cremore-control-key/);
      assert.doesNotMatch(doc, new RegExp(`cremore-${role === "collector" ? "remediator" : "collector"}-keys`));
      assert.match(doc, /defaultMode: 0440\s+items: \[\{ key: private-keys.json, path: private-keys.json \}\]/);
    } else {
      assert.match(doc, /CONTROL_SEALING_KEY/);
      assert.doesNotMatch(doc, /SEALING_PRIVATE_KEYS_FILE|credential-private-keys|cremore-(collector|remediator)-keys/);
    }
  }
  assert.doesNotMatch(deployment(output, "web"), /DATABASE_URL|FINGERPRINT_KEY|SEALING_|credential-private-keys/);
  assert.doesNotMatch(output, /name: SEALING_KEY(?:,|\s)|SEALING_KMS_KEY_ID|SEALING_KEY_VAULT_PATH|PRIVATE KEY-----/);
});

test("collection and action identities remain separate while API and control have none", () => {
  const output = success(helm([
    "aws.webIdentity.enabled=true", "aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/Reader",
    "isolation.remediatorIdentity.aws.webIdentity.enabled=true", "isolation.remediatorIdentity.aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/Actor",
    "gcp.adcSecretName=gcp-reader", "isolation.remediatorIdentity.gcp.adcSecretName=gcp-actor",
    "azure.workloadIdentity.enabled=true", "azure.workloadIdentity.clientId=11111111-1111-1111-1111-111111111111",
    "isolation.remediatorIdentity.azure.workloadIdentity.enabled=true", "isolation.remediatorIdentity.azure.workloadIdentity.clientId=22222222-2222-2222-2222-222222222222",
    "config.awsUsageLookupMode=disabled", "config.awsSecretsInventoryMode=disabled",
    "config.actionExecutionEnabled=true", "config.actionDeletionEnabled=true", "config.rotationExecutionEnabled=true",
  ], ['config.secretManagerAllowedReferences=["arn:aws:secretsmanager:us-east-1:123456789012:secret:reviewed"]']));
  for (const [component, role, adc, client] of [["worker", "Reader", "reader", "11111111"], ["remediator", "Actor", "actor", "22222222"]]) {
    const doc = deployment(output, component);
    assert.equal(envValue(doc, "AWS_ROLE_ARN"), `arn:aws:iam::123456789012:role/${role}`);
    assert.match(doc, new RegExp(`secretName: "gcp-${adc}"`));
    assert.match(doc, /azure.workload.identity\/use: "true"/);
    assert.match(document(output, "ServiceAccount", component), new RegExp(`client-id: ${client}`));
  }
  for (const component of ["api", "control", "web"]) {
    assert.doesNotMatch(deployment(output, component), /AWS_ROLE_ARN|AWS_WEB_IDENTITY_TOKEN_FILE|GOOGLE_APPLICATION_CREDENTIALS|gcp-adc|azure.workload.identity|serviceAccountToken:/);
    assert.doesNotMatch(document(output, "ServiceAccount", component), /azure.workload.identity|eks.amazonaws.com|iam.gke.io/);
  }
  const collector = deployment(output, "worker");
  assert.equal(envValue(collector, "AWS_USAGE_LOOKUP_MODE"), "disabled");
  assert.equal(envValue(collector, "AWS_SECRETS_INVENTORY_MODE"), "disabled");
  assert.match(envValue(collector, "SECRET_MANAGER_ALLOWED_REFERENCES"), /secret:reviewed$/);
  for (const component of ["worker", "control", "remediator"]) {
    for (const name of ["ACTION_EXECUTION_ENABLED", "ACTION_DELETION_ENABLED", "ACTION_ROTATION_ENABLED"]) {
      assert.equal(envValue(deployment(output, component), name), component === "remediator" ? "true" : "false");
    }
  }
});

test("isolated workers receive public OIDC role context without login secrets", () => {
  const output = success(helm([
    "auth.oidc.issuerURL=https://accounts.google.com", "auth.oidc.audience=synthetic-team-audience",
    "auth.oidc.jwksURL=https://www.googleapis.com/oauth2/v3/certs", "auth.oidc.groupsClaim=team_roles",
    "auth.oidc.groups.viewer=viewers@example.invalid", "auth.oidc.groups.analyst=analysts@example.invalid",
    "auth.oidc.groups.remediator=remediators@example.invalid", "auth.oidc.groups.admin=admins@example.invalid",
    "auth.oidc.secret.name=login-client-and-cookie-secret",
  ]));
  const api = deployment(output, "api");
  for (const component of ["worker", "remediator", "control"]) {
    const doc = deployment(output, component);
    assert.equal(envValue(doc, "AUTH_MODE"), "oidc");
    for (const field of ["ISSUER_URL", "JWKS_URL", "AUDIENCE", "GROUPS_CLAIM", "VIEWER_GROUP", "ANALYST_GROUP", "REMEDIATOR_GROUP", "ADMIN_GROUP"]) {
      assert.equal(envValue(doc, `OIDC_${field}`), envValue(api, `OIDC_${field}`));
    }
    assert.doesNotMatch(doc, /login-client-and-cookie-secret|OAUTH2_PROXY|client-secret|cookie-secret|GCP_OAUTH_CLIENT_SECRET/);
  }
});

test("isolated role egress is explicit and does not inherit legacy HTTPS ranges", () => {
  const output = success(helm([], ['isolation.egress.worker=[{"cidr":"198.51.100.10/32","port":443}]', 'isolation.egress.control=[{"cidr":"198.51.100.20/32","port":587}]']));
  for (const component of ["api", "worker", "remediator", "control", "web"]) {
    const doc = policy(output, component);
    assert.doesNotMatch(doc, /0\.0\.0\.0\/0|::\/0/);
    assert.equal(doc.includes("198.51.100.10/32"), component === "worker");
    assert.equal(doc.includes("198.51.100.20/32"), component === "control");
  }
  assert.doesNotMatch(policy(output, "web"), /10\.20\.0\.2\/32/);
});

const siemDestination = 'siem.config.destinations=[{"id":"synthetic","sink":"http","url":"https://siem.example.invalid"}]';
test("isolated SIEM has its own service account and no default destination egress", () => {
  const output = success(helm(["siem.enabled=true"], [siemDestination]));
  const doc = deployment(output, "siem");
  assert.match(doc, /serviceAccountName: chart-check-cremore-siem/);
  assert.match(doc, /ISOLATED_DEPLOYMENT, value: "true"/);
  assert.match(doc, /name: SIEM_DATABASE_URL/);
  assert.doesNotMatch(doc, /FINGERPRINT_KEY|SEALING_|AWS_ROLE_ARN|GOOGLE_APPLICATION_CREDENTIALS|serviceAccountToken:/);
  assert.match(doc, /readOnlyRootFilesystem: true/);
  assert.match(document(output, "ServiceAccount", "siem"), /automountServiceAccountToken: false/);
  assert.doesNotMatch(policy(output, "siem"), /0\.0\.0\.0\/0|::\/0|port: 443/);
  const explicit = success(helm(["siem.enabled=true"], [siemDestination, 'isolation.egress.siem=[{"cidr":"198.51.100.30/32","port":6514}]']));
  assert.match(policy(explicit, "siem"), /cidr: "198.51.100.30\/32"/);
  assert.match(policy(explicit, "siem"), /port: 6514/);
});

test("migration is deliberate, nonroot, TLS-capable and restricted to its database", () => {
  assert.doesNotMatch(defaults(), /kind: Job/);
  const output = success(helm(["isolation.migrationJob.enabled=true", "isolation.migrationJob.revision=reviewed", "databaseTLS.caSecretName=database-trust", "databaseTLS.caSecretKey=postgres-ca.pem"]));
  const job = document(output, "Job", "migrate-reviewed");
  assert.match(job, /command: \["python", "-m", "cremore.db.startup"\]/);
  assert.match(job, /name: cremore-db-migration, key: url/);
  assert.match(job, /serviceAccountName: chart-check-cremore-migrator/);
  assert.match(job, /PGSSLROOTCERT, value: \/run\/db-ca\/ca.crt/);
  assert.match(job, /mountPath: \/run\/db-ca, readOnly: true/);
  assert.match(job, /secretName: database-trust/);
  assert.match(job, /key: postgres-ca.pem, path: ca.crt/);
  assert.match(job, /fsGroup: 65532/);
  assert.match(job, /runAsNonRoot: true/);
  assert.match(job, /readOnlyRootFilesystem: true/);
  assert.match(job, /automountServiceAccountToken: false/);
  assert.doesNotMatch(job, /SEALING_|FINGERPRINT_KEY|AWS_ROLE_ARN|serviceAccountToken:/);
  const egress = policy(output, "migrator");
  assert.match(egress, /10\.20\.0\.2\/32/);
  assert.doesNotMatch(egress, /0\.0\.0\.0\/0|::\/0|port: 443/);
});

test("isolated rendering rejects shared keys, database roles and service accounts", () => {
  for (const [value, message] of [
    ["applicationSecret.sealingKey=old-key", /legacy shared sealing/],
    ["isolation.remediatorPrivateKeysSecret=cremore-collector-keys", /distinct non-empty secrets/],
    ["isolation.controlKeySecret=cremore-collector-keys", /distinct non-empty secrets/],
    ["internalTLS.apiSecretName=cremore-collector-keys", /must not be reused/],
    ["isolation.databaseSecrets.control=cremore-db-api", /distinct database secrets/],
    ["serviceAccounts.control.name=chart-check-cremore-api", /distinct non-default service accounts/],
    ["serviceAccounts.migrator.name=default", /distinct non-default service accounts/],
    ["serviceAccounts.remediator.automountServiceAccountToken=true", /automatic Kubernetes API token/],
    ["networkPolicy.enabled=false", /NetworkPolicy/],
    ["networkPolicy.databaseCIDR=0.0.0.0/0", /explicit database network/],
  ]) denied([value], message);
  denied(["siem.enabled=true", "siem.databaseUrlSecret.name=cremore-db-api"], /own database secret/, [siemDestination]);
  denied(["siem.enabled=true", "siem.tokenSecretName=cremore-collector-keys"], /must not be reused/, [siemDestination]);
  denied(["siem.enabled=true", "siem.tlsSecretName=cremore-db-api"], /separate from application/, [siemDestination]);
});

test("control and noncredential workloads cannot request cloud identities or metadata egress", () => {
  for (const component of ["api", "control", "web", "siem", "migrator"]) {
    denied([], /only collector\/remediator service accounts/, [`serviceAccounts.${component}.annotations={"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/Reader"}`]);
  }
  denied([], /explicit destination CIDRs/, ['isolation.egress.siem=[{"cidr":"0.0.0.0/0","port":443}]']);
  denied([], /only collector\/remediator may reach/, ['isolation.egress.control=[{"cidr":"169.254.170.23/32","port":80}]']);
  denied([], /explicit destination CIDRs/, ['isolation.egress.worker=[{"cidr":"198.51.100.4/32","port":443.5}]']);
});

test("remediator workload credentials receive the same shape checks as collector credentials", () => {
  const aws = ["isolation.remediatorIdentity.aws.webIdentity.enabled=true", "isolation.remediatorIdentity.aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/Actor"];
  for (const value of ["expirationSeconds=12.5", "expirationSeconds=599", "expirationSeconds=86401", "audience="]) {
    denied([...aws, `isolation.remediatorIdentity.aws.webIdentity.${value}`], /remediator AWS token/);
  }
  denied([...aws, "isolation.remediatorIdentity.aws.rolesAnywhere.enabled=true"], /Choose one remediator/);
  const azure = ["isolation.remediatorIdentity.azure.workloadIdentity.enabled=true", "isolation.remediatorIdentity.azure.workloadIdentity.clientId=22222222-2222-2222-2222-222222222222"];
  for (const value of ["clientId=invalid", "tenantId=invalid", "tokenExpirationSeconds=3599", "tokenExpirationSeconds=3600.5"]) {
    denied([...azure, `isolation.remediatorIdentity.azure.workloadIdentity.${value}`], /remediator Azure/);
  }
  denied(["isolation.remediatorIdentity.gcp.adcSecretName=actor", "isolation.remediatorIdentity.gcp.adcSecretKey="], /GCP ADC secret key/);
});

test("collector and remediator cannot reuse configured cloud identity objects", () => {
  denied(["aws.webIdentity.enabled=true", "aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/Shared", "isolation.remediatorIdentity.aws.webIdentity.enabled=true", "isolation.remediatorIdentity.aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/Shared"], /must not share an AWS role/);
  denied(["aws.rolesAnywhere.enabled=true", "aws.rolesAnywhere.secretName=shared", "isolation.remediatorIdentity.aws.rolesAnywhere.enabled=true", "isolation.remediatorIdentity.aws.rolesAnywhere.secretName=shared"], /must not share Roles Anywhere/);
  denied(["gcp.adcSecretName=shared", "isolation.remediatorIdentity.gcp.adcSecretName=shared"], /must not share a GCP ADC secret/);
  denied(["azure.workloadIdentity.enabled=true", "azure.workloadIdentity.clientId=11111111-1111-1111-1111-111111111111", "isolation.remediatorIdentity.azure.workloadIdentity.enabled=true", "isolation.remediatorIdentity.azure.workloadIdentity.clientId=11111111-1111-1111-1111-111111111111"], /must not share an Azure client ID/);
  denied([], /distinct cloud workload identities/, [
    'serviceAccounts.worker.annotations={"iam.gke.io/gcp-service-account":"shared@project.iam.gserviceaccount.com"}',
    'serviceAccounts.remediator.annotations={"iam.gke.io/gcp-service-account":"shared@project.iam.gserviceaccount.com"}',
  ]);
});
