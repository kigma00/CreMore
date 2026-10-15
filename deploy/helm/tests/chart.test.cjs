// Pure Helm rendering checks: no Kubernetes context, provider access, credentials
// or network are used. Uses the pinned image, or CREMORE_HELM_BINARY at 3.17.2.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const os = require("node:os");
const { readFileSync, writeFileSync, rmSync, mkdtempSync, mkdirSync, cpSync } = require("node:fs");
const { spawnSync } = require("node:child_process");

const chart = path.resolve(__dirname, "..");
const image = "alpine/helm:3.17.2@sha256:b80eb190fca14707e94a5090235a3f1bf2f206f26761f2890d16a1e570386236";
const nativeHelm = process.env.CREMORE_HELM_BINARY;
if (nativeHelm) {
  const version = success(spawnSync(nativeHelm, ["version", "--short"], { encoding: "utf8", timeout: 10000 }));
  assert.match(version, /^v3\.17\.2(?:\+|\s|$)/, "native rendering requires Helm 3.17.2");
}
function helm(action, values = [], jsonValues = [], chartDirectory = chart) {
  const args = nativeHelm ? [action] : ["run", "--rm", "--network", "none", "--pull", "never", "-v", `${chartDirectory}:/chart:ro`, image, action];
  if (action === "template") args.push("chart-check");
  args.push(nativeHelm ? chartDirectory : "/chart");
  for (const value of values) args.push(/=(?:true|false)$/.test(value) ? "--set" : "--set-string", value);
  for (const value of jsonValues) args.push("--set-json", value);
  return spawnSync(nativeHelm || "docker", args, { encoding: "utf8", timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
}
function compose(overrides = {}, files = [], envFile = path.join(__dirname, "empty.env")) {
  const root = path.resolve(chart, "../..");
  // Retain only process-launch / Docker settings; all application values are
  // synthetic and the explicit empty file bypasses the operator's local .env.
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    /^(path|systemroot|windir|comspec|temp|tmp|userprofile|appdata|localappdata|programdata|programfiles(?:\(x86\))?|programw6432|homedrive|homepath|home|docker_host|docker_context|docker_config|docker_tls_verify|docker_cert_path)$/i.test(name)));
  const env = { ...inherited, API_ADMIN_TOKEN: "0".repeat(32), POSTGRES_PASSWORD: "0".repeat(32), FINGERPRINT_KEY: "0".repeat(64),
    SCAN_SCHEDULES_MODE: "enabled", SCAN_SQS_MODE: "enabled", SCAN_PUBSUB_MODE: "enabled",
    SCAN_SERVICEBUS_MODE: "enabled", SCAN_CHANGE_FEEDS_MODE: "enabled",
    SCAN_SQS_QUEUE_URL: "", SCAN_SQS_PROFILE_ID: "", SCAN_SQS_DEDICATED_ACKNOWLEDGED: "false",
    SCAN_INVENTORY_MANIFESTS: "", ...overrides };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  return spawnSync("docker", ["compose", "--env-file", envFile,
    "-f", path.join(root, "docker-compose.yml"), ...files.flatMap(file => ["-f", path.isAbsolute(file) ? file : path.join(root, file)]), "config", "--format", "json"], {
    encoding: "utf8", timeout: 60000, env,
  });
}
function success(result) {
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  return result.stdout;
}
function deployment(output, component) {
  const doc = output.split(/^---\s*$/m).find((value) => value.includes("kind: Deployment") && new RegExp(`^  name: .*-${component}$`, "m").test(value));
  assert.ok(doc, `${component} deployment rendered`);
  return doc;
}
function envValue(doc, name) {
  const match = doc.match(new RegExp(`name: ${name}, value: ("(?:\\\\.|[^"\\\\])*")`));
  assert.ok(match, `${name} has a quoted environment value`);
  return JSON.parse(match[1]);
}

test("GCP OAuth app configuration reaches only API and callback queries are not request-logged", () => {
  const output = success(helm("template", ["gcp.oauth.secretName=google-app", "gcp.oauth.redirectUri=https://cremore.example/gcp/oauth/callback"]));
  const api = deployment(output, "api");
  assert.match(api, /name: GCP_OAUTH_CLIENT_ID/);
  assert.match(api, /name: GCP_OAUTH_CLIENT_SECRET/);
  assert.match(api, /name: "google-app"/);
  assert.equal(envValue(api, "GCP_OAUTH_REDIRECT_URI"), "https://cremore.example/gcp/oauth/callback");
  for (const name of ["worker", "web"]) assert.doesNotMatch(deployment(output, name), /name: GCP_OAUTH_/);
  assert.match(deployment(output, "web"), /--request-logging=false/);
});
test("ticket-system plugins reach the API and worker, empty by default, never the web", () => {
  const fallback = success(helm("template"));
  for (const name of ["api", "worker"]) assert.equal(envValue(deployment(fallback, name), "TICKET_SYSTEM_PLUGINS"), "");
  const output = success(helm("template", ["config.ticketSystemPlugins=jira"]));
  for (const name of ["api", "worker"]) assert.equal(envValue(deployment(output, name), "TICKET_SYSTEM_PLUGINS"), "jira");
  assert.doesNotMatch(deployment(output, "web"), /TICKET_SYSTEM_PLUGINS/);
  const services = JSON.parse(success(compose({ TICKET_SYSTEM_PLUGINS: "jira" }))).services;
  for (const name of ["api", "worker"]) assert.equal(services[name].environment.TICKET_SYSTEM_PLUGINS, "jira");
  assert.equal(JSON.parse(success(compose())).services.api.environment.TICKET_SYSTEM_PLUGINS, "");
});
function networkPolicy(output, component) {
  const doc = output.split(/^---\s*$/m).find((value) => value.includes("kind: NetworkPolicy") && new RegExp(`^  name: .*-${component}$`, "m").test(value));
  assert.ok(doc, `${component} network policy rendered`);
  return doc;
}
function probeBlock(doc, probe) {
  return doc.match(new RegExp(`^          ${probe}:\\n([\\s\\S]*?)(?=^          [a-zA-Z]|^        - name:)`, "m"))?.[1];
}
function verifyProbes(output) {
  for (const component of ["api", "web"]) {
    const doc = deployment(output, component);
    for (const probe of ["readinessProbe", "livenessProbe"]) {
      const block = probeBlock(doc, probe);
      assert.ok(block, `${component} ${probe} exists`);
      assert.match(block, /path: \/healthz/, `${component} ${probe} probes health route`);
      if (component === "api") assert.match(block, /scheme: HTTPS/, `TLS API ${probe} must use HTTPS`);
      else assert.doesNotMatch(block, /scheme: HTTPS/, `${component} plaintext local health endpoint must not use HTTPS`);
    }
  }
  // The worker has no HTTP port: liveness is the freshness of its heartbeat file.
  const worker = deployment(output, "worker");
  for (const probe of ["readinessProbe", "livenessProbe"]) {
    const block = probeBlock(worker, probe);
    assert.ok(block, `worker ${probe} exists`);
    assert.match(block, /exec:/, `worker ${probe} is an exec probe`);
    assert.match(block, /cremore-worker\.heartbeat/, `worker ${probe} checks the heartbeat file`);
    assert.doesNotMatch(block, /httpGet/, "worker has no HTTP health endpoint");
  }
  assert.doesNotMatch(worker, /containerPort:/, "worker exposes no port");
}

test("Pod Identity agent access is opt-in and restricted to backend workloads", () => {
  const off = success(helm("template"));
  assert.doesNotMatch(off, /169\.254\.170\.23|fd00:ec2::23/);
  const on = success(helm("template", ["networkPolicy.eksPodIdentity=true"]));
  for (const component of ["api", "worker"]) {
    assert.match(networkPolicy(on, component), /169\.254\.170\.23\/32/);
    assert.match(networkPolicy(on, component), /fd00:ec2::23\/128/);
  }
  assert.doesNotMatch(networkPolicy(on, "web"), /169\.254\.170\.23/);
});

test("generic Kubernetes projected AWS identity reaches API and worker only", () => {
  const output = success(helm("template", ["aws.webIdentity.enabled=true", "aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/cremore/Reader"]));
  for (const name of ["api", "worker"]) {
    const doc = deployment(output, name);
    assert.equal(envValue(doc, "AWS_ROLE_ARN"), "arn:aws:iam::123456789012:role/cremore/Reader");
    assert.match(doc, /serviceAccountToken:\s+audience: "sts.amazonaws.com"\s+expirationSeconds: 3600\s+path: token/);
    assert.match(doc, /mountPath: \/run\/cremore-aws-identity, readOnly: true/);
  }
  assert.doesNotMatch(deployment(output, "web"), /AWS_ROLE_ARN|aws-web-identity/);
  for (const values of [
    ["aws.webIdentity.enabled=true"],
    ["aws.webIdentity.enabled=true", "aws.rolesAnywhere.enabled=true"],
    ["aws.rolesAnywhere.enabled=true"],
    ["aws.rolesAnywhere.enabled=true", "aws.rolesAnywhere.secretName=ra", "networkPolicy.eksPodIdentity=true"],
    ["aws.webIdentity.enabled=true", "aws.webIdentity.roleArn=arn:aws:iam::123456789012:role/Reader", "aws.webIdentity.expirationSeconds=12.5"],
  ]) assert.notEqual(helm("template", values).status, 0);
});

test("Roles Anywhere mounts rotating files without exposing them to web", () => {
  const output = success(helm("template", ["aws.rolesAnywhere.enabled=true", "aws.rolesAnywhere.secretName=ra"]));
  for (const name of ["api", "worker"]) {
    const doc = deployment(output, name);
    assert.match(doc, /AWS_ROLES_ANYWHERE_CONFIG, value: \/run\/cremore-roles-anywhere\/roles-anywhere.json/);
    assert.match(doc, /secretName: "ra"\s+defaultMode: 0440/);
    assert.doesNotMatch(doc, /subPath:/);
  }
  assert.doesNotMatch(deployment(output, "web"), /roles-anywhere|AWS_PROFILE/);
  const services = JSON.parse(success(compose({ AWS_ROLES_ANYWHERE_DIRECTORY: "/synthetic/identity", AWS_SIGNING_HELPER_PATH: "/synthetic/helper" }, ["deploy/compose/identity/aws-roles-anywhere.yml"]))).services;
  for (const name of ["api", "worker"]) {
    assert.equal(services[name].environment.AWS_PROFILE, "cremore-roles-anywhere");
    assert.equal(services[name].environment.AWS_ACCESS_KEY_ID, "");
    assert.equal(services[name].environment.AWS_EC2_METADATA_DISABLED, "true");
    const mount = services[name].volumes.find(v => v.target === "/run/cremore-roles-anywhere");
    assert.equal(mount.read_only, true);
    assert.equal(mount.bind.create_host_path, false);
  }
  assert.equal(services.web.environment.AWS_ROLES_ANYWHERE_CONFIG, undefined);
});

test("Compose restarts core services and EC2 overlay selects the instance role", () => {
  const config = JSON.parse(success(compose({}, ["deploy/compose/ec2-instance-profile.yml"])));
  for (const component of ["db", "api", "worker", "web"]) assert.equal(config.services[component].restart, "unless-stopped");
  for (const component of ["api", "worker"]) {
    const env = config.services[component].environment;
    assert.equal(env.AWS_EC2_METADATA_DISABLED, "false");
    assert.equal(env.AWS_SHARED_CREDENTIALS_FILE, "/dev/null");
    assert.equal(env.AWS_SSO_DISCOVERY_MODE, "disabled");
  }
});

test("default chart renders the Python platform with TLS-correct probes", () => {
  success(helm("lint"));
  const output = success(helm("template"));
  verifyProbes(output);
  const api = deployment(output, "api");
  const worker = deployment(output, "worker");
  const web = deployment(output, "web");
  assert.match(api, /command: \["cremore-api"\]/);
  assert.match(worker, /command: \["cremore-worker"\]/);
  assert.match(api, /image: "ghcr\.io\/y4rvin\/cremore-api:0\.1\.0"/);
  assert.match(worker, /image: "ghcr\.io\/y4rvin\/cremore-worker:0\.1\.0"/);
  for (const doc of [api, worker]) {
    assert.match(doc, /name: CREDENTIAL_VERIFICATION_MODE, value: "enabled"/);
    assert.doesNotMatch(doc, /CREDENTIAL_VERIFICATION_ACKNOWLEDGED/);
    assert.match(doc, /name: ACTION_EXECUTION_ENABLED, value: "false"/);
    assert.match(doc, /name: ACTION_ROTATION_ENABLED, value: "false"/);
    assert.match(doc, /name: IAM_POTENTIAL_ACCESS_MODE, value: "enabled"/);
    assert.match(doc, /name: AWS_EC2_METADATA_DISABLED, value: "true"/);
    assert.match(doc, /name: FINGERPRINT_KEY\s+valueFrom: \{ secretKeyRef: \{ name: cremore-secrets, key: fingerprint-key/);
    assert.match(doc, /name: DATABASE_URL\s+valueFrom: \{ secretKeyRef: \{ name: cremore-database, key: url/);
    assert.doesNotMatch(doc, /DETECTOR_ENGINE|SOURCE_PROFILE|API_ADMIN_TOKEN/i);
    for (const mode of ["SCAN_SCHEDULES_MODE", "SCAN_SQS_MODE", "SCAN_PUBSUB_MODE", "SCAN_SERVICEBUS_MODE", "SCAN_CHANGE_FEEDS_MODE"]) {
      assert.equal(envValue(doc, mode), "enabled");
    }
    assert.equal(envValue(doc, "SCAN_SQS_DEDICATED_ACKNOWLEDGED"), "false");
    for (const name of ["SCAN_SQS_QUEUE_URL", "SCAN_SQS_PROFILE_ID"]) assert.equal(envValue(doc, name), "");
    assert.equal(envValue(doc, "SCAN_INVENTORY_MANIFESTS"), "{}");
    assert.doesNotMatch(doc, /SCAN_EVENTS_/, "the signed event webhook is gone, along with its Secret reference");
  }
  // API-only surfaces: TLS files, bind address, OIDC role groups, inventory flag.
  assert.match(api, /name: API_BIND, value: "0\.0\.0\.0:8080"/);
  assert.match(api, /name: TLS_CERT_FILE, value: \/run\/api-tls\/tls\.crt/);
  assert.match(api, /name: AWS_SECRETS_INVENTORY_MODE, value: "enabled"/);
  // Every credential-mutating capability is off. Its knobs are API-only, except the plan execution switches: a plan
  // on another provider's credential runs in the worker (docs/PROVIDER_ACTIONS.md), which checks them again.
  assert.match(api, /name: AWS_USAGE_LOOKUP_MODE, value: "enabled"/);
  assert.match(api, /name: LEARNED_FP_MODE, value: "enabled"/);
  assert.match(worker, /name: LEARNED_FP_MODE, value: "enabled"/);
  assert.match(api, /name: ACTION_DELETION_ENABLED, value: "false"/);
  assert.match(worker, /name: ACTION_DELETION_ENABLED, value: "false"/);
  assert.match(api, /name: ROTATION_SECRET_ARNS, value: ""/);
  assert.match(api, /name: SECRET_MANAGER_ALLOWED_REFERENCES, value: ""/);
  assert.match(api, /name: AWS_ONBOARDING_TEMPLATE_URL, value: ""/);
  assert.doesNotMatch(worker, /AWS_USAGE_LOOKUP_MODE|ROTATION_SECRET_ARNS|SECRET_MANAGER_ALLOWED_REFERENCES/);
  for (const group of ["VIEWER", "ANALYST", "REMEDIATOR", "ADMIN"]) assert.match(api, new RegExp(`name: OIDC_${group}_GROUP, value: "cremore-`));
  assert.match(api, /name: OIDC_ISSUER_URL, value: "https:\/\/idp\.example\.com"/);
  assert.doesNotMatch(api, /name: API_TOKEN/);
  assert.doesNotMatch(worker, /OIDC_|TLS_CERT_FILE|API_BIND|AWS_SECRETS_INVENTORY_MODE/);
  assert.match(worker, /name: WORKER_HEARTBEAT_FILE, value: \/tmp\/cremore-worker\.heartbeat/);
  // web talks to the API over the internal TLS service and forwards the OIDC token.
  assert.match(web, /name: CREMORE_API_URL, value: "https:\/\/chart-check-cremore-api:8443"/);
  assert.match(web, /name: CREMORE_AUTH_MODE, value: "oidc"/);
  assert.match(web, /name: oauth2-proxy/);
  assert.match(web, /--scope=openid profile email groups offline_access/);
  assert.match(web, /--cookie-refresh=1h/);
  assert.match(web, /--cookie-expire=8h/);
  assert.doesNotMatch(web, /DATABASE_URL|FINGERPRINT_KEY|OIDC_.*_GROUP|SCAN_/);
  // No secret store env unless enabled; never key material anywhere.
  assert.doesNotMatch(output, /SECRET_STORE_URL|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|SecretString/);
  assert.doesNotMatch(output, /app\.kubernetes\.io\/component: (action-executor|rotation-automation)/);
});

test("static secret-store token reaches only the worker", () => {
  const output = success(helm("template", ["secretStore.enabled=true", "secretStore.secretName=cremore-openbao"]));
  const worker = deployment(output, "worker");
  assert.match(worker, /name: SECRET_STORE_URL\s+valueFrom: \{ secretKeyRef: \{ name: cremore-openbao, key: url/);
  assert.match(worker, /name: SECRET_STORE_AUTH_MODE, value: "token"/);
  assert.match(worker, /name: SECRET_STORE_TOKEN\s+valueFrom: \{ secretKeyRef: \{ name: cremore-openbao, key: token/);
  assert.match(worker, /name: SECRET_STORE_MOUNT, value: "secret"/);
  assert.doesNotMatch(deployment(output, "api"), /SECRET_STORE/);
  assert.doesNotMatch(deployment(output, "web"), /SECRET_STORE/);
  const missing = helm("template", ["secretStore.enabled=true"]);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stdout + missing.stderr, /secretStore.secretName is required/);
});

test("Vault Kubernetes auth projects an audience-bound worker token and no static token", () => {
  const output = success(helm("template", [
    "secretStore.enabled=true",
    "secretStore.secretName=cremore-openbao",
    "secretStore.authMode=kubernetes",
    "secretStore.kubernetes.role=cremore-worker",
  ]));
  const worker = deployment(output, "worker");
  assert.match(worker, /automountServiceAccountToken: false/);
  assert.match(worker, /name: SECRET_STORE_AUTH_MODE, value: "kubernetes"/);
  assert.match(worker, /name: SECRET_STORE_KUBERNETES_ROLE, value: "cremore-worker"/);
  assert.match(worker, /name: SECRET_STORE_KUBERNETES_AUTH_MOUNT, value: "kubernetes"/);
  assert.match(worker, /name: SECRET_STORE_KUBERNETES_TOKEN_FILE, value: \/run\/cremore-vault\/token/);
  assert.match(worker, /name: vault-workload-token, mountPath: \/run\/cremore-vault, readOnly: true/);
  assert.match(worker, /serviceAccountToken:\s+path: token\s+audience: "vault"\s+expirationSeconds: 3600/);
  assert.doesNotMatch(worker, /name: SECRET_STORE_TOKEN/);
  for (const [values, expected] of [
    [["secretStore.enabled=true", "secretStore.secretName=cremore-openbao", "secretStore.authMode=invalid"], /authMode must be token or kubernetes/],
    [["secretStore.enabled=true", "secretStore.secretName=cremore-openbao", "secretStore.authMode=kubernetes"], /kubernetes.role is required/],
    [["secretStore.enabled=true", "secretStore.secretName=cremore-openbao", "secretStore.mount=../secret"], /mount must be a single safe path segment/],
  ]) {
    const result = helm("template", values);
    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, expected);
  }
});

test("OIDC refresh settings and scopes are the installer's choice", () => {
  const custom = success(helm("template", [
    "auth.oidc.oauth2Proxy.cookieRefresh=30m",
    "auth.oidc.oauth2Proxy.cookieExpire=12h",
    "auth.oidc.jwksURL=https://keys.example.test/company.json",
  ], ['auth.oidc.scopes=["openid","email"]']));
  const web = deployment(custom, "web");
  assert.match(web, /--cookie-refresh=30m/);
  assert.match(web, /--cookie-expire=12h/);
  assert.match(web, /--scope=openid email/);
  assert.equal(envValue(deployment(custom, "api"), "OIDC_JWKS_URL"), "https://keys.example.test/company.json");
  assert.doesNotMatch(deployment(custom, "worker"), /OIDC_JWKS_URL/);
});

test("key actions are typed opt-ins; deletion still needs execution", () => {
  const on = success(helm("template", ["config.rotationExecutionEnabled=true", "networkPolicy.enabled=false"]));
  assert.match(deployment(on, "api"), /name: ACTION_ROTATION_ENABLED, value: "true"/);
  assert.match(deployment(on, "worker"), /name: ACTION_ROTATION_ENABLED, value: "false"/);
  for (const [name, values, jsonValues, expected] of [
    ["typed flag", [], ['config.rotationExecutionEnabled="true"'], /rotationExecutionEnabled must be a boolean/],
    ["typed action flag", [], ['config.actionExecutionEnabled="yes"'], /actionExecutionEnabled must be a boolean/],
    ["deletion without execution", ["config.actionDeletionEnabled=true"], [], /actionDeletionEnabled requires config.actionExecutionEnabled=true/],
  ]) {
    const result = helm("template", values, jsonValues);
    assert.notEqual(result.status, 0, name);
    assert.match(result.stdout + result.stderr, expected, name);
  }
});

test("the chart renders OIDC; legacy values install and infrastructure choices are not render failures", () => {
  const output = success(helm("template"));
  for (const component of ["api", "worker"]) assert.equal(envValue(deployment(output, component), "AUTH_MODE"), "oidc");
  assert.doesNotMatch(output, /API_TOKEN|DEPLOYMENT_MODE/);
  const legacy = success(helm("template", ["deploymentMode=production", "auth.mode=oidc", "applicationSecret.apiTokenKey=api-token"]));
  assert.equal(legacy, output, "a pre-removal values file renders exactly the same manifests");
  const chosen = success(helm("template", [
    "ingress.enabled=false", "networkPolicy.enabled=false", "auth.oidc.issuerURL=http://keycloak.internal/realms/cremore",
    "auth.oidc.groups.admin=security", "auth.oidc.groups.viewer=security",
  ]));
  assert.doesNotMatch(chosen, /^kind: (Ingress|NetworkPolicy)$/m);
  const local = helm("template", ["auth.mode=local"]);
  assert.notEqual(local.status, 0);
  assert.match(local.stdout + local.stderr, /this chart renders OIDC/);
});

test("GitHub Enterprise Server hosts reach the workloads", () => {
  // A connection records its own host, but cross-host verification only ever
  // contacts hosts on this list, so an unlisted GHES host is never retried.
  const none = success(helm("template", []));
  const listed = success(helm("template",
    ["config.githubEnterpriseHosts[0]=ghe.example.com", "config.githubEnterpriseHosts[1]=ghe2.example.com"]));
  for (const component of ["api", "worker"]) {
    assert.equal(envValue(deployment(none, component), "GITHUB_ENTERPRISE_HOSTS"), "");
    assert.equal(envValue(deployment(listed, component), "GITHUB_ENTERPRISE_HOSTS"),
                 "ghe.example.com,ghe2.example.com");
  }
});

test("Identity Center access is off on a cluster but stays an operator's choice", () => {
  // It does work here, but only with a writable token cache (botocore rewrites
  // it on the hourly renewal) and a human re-login about every 90 days, so the
  // chart makes the safe path the default rather than forbidding the feature.
  const fresh = success(helm("template", []));
  const opted = success(helm("template", ["config.ssoDiscoveryMode=enabled"]));
  for (const component of ["api", "worker"]) {
    assert.match(deployment(fresh, component), /name: AWS_SSO_DISCOVERY_MODE, value: "disabled"/);
    assert.match(deployment(opted, component), /name: AWS_SSO_DISCOVERY_MODE, value: "enabled"/);
  }
});

test("organization discovery is left to the dashboard rather than pinned by the chart", () => {
  // Its ExternalId, OU scope and sweep switch are installation settings an
  // administrator sets in the dashboard, so the chart pins none of them and the
  // code default (allowed) lets that switch work without a helm upgrade.
  const rendered = success(helm("template", []));
  for (const component of ["api", "worker"]) {
    assert.doesNotMatch(deployment(rendered, component), /AWS_ORG_DISCOVERY_EXTERNAL_ID/);
    assert.doesNotMatch(deployment(rendered, component), /AWS_ORG_DISCOVERY_MODE/);
  }
});

test("the plan execution switches reach the worker that runs provider plans, and rotation stays API-only", () => {
  const output = success(helm("template", ["config.actionExecutionEnabled=true", "config.actionDeletionEnabled=true"]));
  for (const component of ["api", "worker"]) {
    assert.equal(envValue(deployment(output, component), "ACTION_EXECUTION_ENABLED"), "true");
    assert.equal(envValue(deployment(output, component), "ACTION_DELETION_ENABLED"), "true");
  }
  assert.equal(envValue(deployment(output, "worker"), "ACTION_ROTATION_ENABLED"), "false");
});

test("verification is on by default, needs no acknowledgement and can be locked off", () => {
  const locked = success(helm("template", ["config.verificationMode=disabled"]));
  const legacy = success(helm("template", ["config.verificationMode=enabled", "config.verificationAcknowledged=true", "networkPolicy.httpsEgressCIDRs[0]=198.51.100.0/24"]));
  for (const component of ["api", "worker"]) {
    assert.match(deployment(locked, component), /name: CREDENTIAL_VERIFICATION_MODE, value: "disabled"/);
    assert.match(deployment(legacy, component), /name: CREDENTIAL_VERIFICATION_MODE, value: "enabled"/);
  }
});

test("default Compose runs api and worker from the Python image with everything mutating off", () => {
  const root = path.resolve(chart, "../..");
  const result = compose({ SCAN_INVENTORY_MANIFESTS: undefined });
  assert.equal(result.error, undefined, "Compose configuration must be available");
  assert.equal(result.status, 0, "Compose configuration must resolve");
  const services = JSON.parse(result.stdout).services;
  // One Python image: api builds it, worker reuses the exact same tag (no
  // separate build that could go stale and silently run older code).
  assert.match(services.api.build.dockerfile, /python\.Dockerfile$/);
  assert.equal(services.api.build.target, undefined);
  assert.equal(services.worker.build, undefined);
  assert.equal(services.worker.image, services.api.image);
  for (const component of ["api", "worker"]) {
    assert.equal(services[component].environment.CREDENTIAL_VERIFICATION_MODE, "enabled");
    assert.equal(services[component].environment.CREDENTIAL_VERIFICATION_ACKNOWLEDGED, undefined);
    assert.equal(services[component].environment.ACTION_ROTATION_ENABLED, "false");
    assert.equal(services[component].environment.ACTION_EXECUTION_ENABLED, "false");
    for (const mode of ["SCAN_SCHEDULES_MODE", "SCAN_SQS_MODE", "SCAN_PUBSUB_MODE", "SCAN_SERVICEBUS_MODE", "SCAN_CHANGE_FEEDS_MODE"]) {
      assert.equal(services[component].environment[mode], "enabled");
    }
    assert.ok(!Object.keys(services[component].environment).some((name) => name.startsWith("SCAN_EVENTS_")),
      "the signed event webhook is gone; nothing should still carry its configuration");
    assert.equal(services[component].environment.SCAN_SQS_DEDICATED_ACKNOWLEDGED, "false");
    assert.deepEqual(JSON.parse(services[component].environment.SCAN_INVENTORY_MANIFESTS), {});
  }
  assert.deepEqual(services.api.command, ["cremore-api"]);
  assert.deepEqual(services.worker.command, ["cremore-worker"]);
  // The operator's AWS login reaches api and worker: config read-only, only the
  // SSO/login token caches writable so Identity Center sessions refresh. Web never sees it.
  for (const component of ["api", "worker"]) {
    const mount = (target) => services[component].volumes.find((volume) => volume.target === target);
    assert.ok(mount("/cremore-home/.aws")?.read_only === true, `${component} mounts ~/.aws read-only`);
    for (const cache of ["sso", "login"]) {
      const writable = mount(`/cremore-home/.aws/${cache}/cache`);
      assert.ok(writable && !writable.read_only, `${component} can refresh the ${cache} token cache`);
    }
    assert.equal(services[component].volumes.length, 3, "no other host path is mounted");
    // Opt-in: without AWS_CONFIG_DIR an empty in-repo placeholder is mounted, and
    // no host path is ever auto-created (Linux Docker would create it as root).
    for (const volume of services[component].volumes) {
      assert.match(volume.source.replaceAll("\\", "/"), /deploy\/compose\/no-aws-login/);
      assert.notEqual(volume.bind?.create_host_path, true, "host path creation must stay disabled (Compose may omit false)");
    }
    assert.equal(services[component].user, "65532:65532");
    assert.equal(services[component].environment.HOME, "/cremore-home");
  }
  assert.ok(!(services.web.volumes || []).some((volume) => volume.target.includes(".aws")));
  assert.equal(services.web.environment.CREMORE_API_URL, "http://api:8080");
  const dockerfile = readFileSync(path.join(root, "deploy/docker/python.Dockerfile"), "utf8");
  // Build and runtime stages are digest-pinned; the runtime is the minimal
  // image (no shell or package manager), runs unprivileged, and ships no pip.
  const stages = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map(match => match[1]);
  assert.equal(stages.length, 2);
  for (const image of stages) assert.match(image, /@sha256:[0-9a-f]{64}$/);
  assert.match(stages[0], /-dev@sha256:/);
  assert.doesNotMatch(stages[1], /-dev@sha256:/);
  assert.match(dockerfile, /^USER 65532:65532$/m);
  assert.match(dockerfile, /pip uninstall -y pip setuptools wheel/);
});

test("configured scanning forwards exact references only to API and worker without changing ingress or source infrastructure", () => {
  const profile = "11111111-1111-4111-8111-111111111111";
  const queue = "https://sqs.us-east-1.amazonaws.com/123456789012/cremore-dedicated";
  const bindings = { "22222222-2222-4222-8222-222222222222/approved-bucket": {
    manifest_bucket: "existing-reports", manifest_key: "reports/2026-09-15/manifest.json",
  } };
  const output = success(helm("template", [
    `scanning.sqs.profileId=${profile}`, `scanning.sqs.queueURL=${queue}`,
    "scanning.sqs.dedicatedAcknowledged=true",
  ], [`scanning.inventoryManifests=${JSON.stringify(bindings)}`]));
  const baseline = success(helm("template"));
  for (const component of ["api", "worker"]) {
    const doc = deployment(output, component);
    // The modes only allow a trigger; the switch that starts one is an Admin's.
    for (const mode of ["SCAN_SCHEDULES_MODE", "SCAN_SQS_MODE", "SCAN_PUBSUB_MODE", "SCAN_SERVICEBUS_MODE", "SCAN_CHANGE_FEEDS_MODE"]) {
      assert.equal(envValue(doc, mode), "enabled");
    }
    assert.equal(envValue(doc, "SCAN_SQS_DEDICATED_ACKNOWLEDGED"), "true");
    assert.equal(envValue(doc, "SCAN_SQS_PROFILE_ID"), profile);
    assert.equal(envValue(doc, "SCAN_SQS_QUEUE_URL"), queue);
    assert.deepEqual(JSON.parse(envValue(doc, "SCAN_INVENTORY_MANIFESTS")), bindings);
    assert.equal(envValue(doc, "CREDENTIAL_VERIFICATION_MODE"), "enabled");
    assert.equal(envValue(doc, "ACTION_EXECUTION_ENABLED"), "false");
    assert.equal(networkPolicy(output, component), networkPolicy(baseline, component));
  }
  assert.equal(deployment(output, "web"), deployment(baseline, "web"), "no scan settings or signing key reach web");
  const ingress = text => text.split(/^---\s*$/m).find(doc => /^kind: Ingress$/m.test(doc));
  assert.equal(ingress(output), ingress(baseline), "webhook enablement adds no public route or OIDC bypass");
  const kinds = text => [...text.matchAll(/^kind: (\S+)$/gm)].map(match => match[1]).sort();
  assert.deepEqual(kinds(output), kinds(baseline), "no source/cloud resources or Secret objects are provisioned");
  assert.doesNotMatch(output, /^kind: (Secret|Bucket|Queue|Rule|Trail)$/m);
});

test("Compose pins the database image by digest and runs everything else as non-root", () => {
  // 17.4-alpine carried a critical OpenSSL flaw, so the image is a digest: a
  // rebuild cannot move to one nobody reviewed, and re-pinning stays deliberate.
  // The database keeps the image's own root-then-gosu entrypoint, because that
  // is what can chown a host directory mounted in place of the named volume.
  const services = JSON.parse(compose().stdout).services;
  assert.match(services.db.image, /^postgres:17-alpine@sha256:[0-9a-f]{64}$/, services.db.image);
  assert.equal(services.db.user, undefined, "the database uses the image's entrypoint");
  // api and worker are told who to be here so they can read the operator's own
  // ~/.aws; web carries it in its image, which is where the check belongs.
  for (const name of ["api", "worker"]) {
    assert.ok(services[name].user, `${name} must declare a non-root user`);
    assert.doesNotMatch(String(services[name].user), /^0(:|$)/, `${name} must not be root`);
  }
  const webImage = readFileSync(path.join(chart, "..", "..", "web", "Dockerfile"), "utf8");
  assert.match(webImage, /^USER 65532:65532$/m, "the web image must not run as root");
});

test("Compose scanning interpolation preserves configured JSON and limits HMAC to API and worker", () => {
  const bindings = { "22222222-2222-4222-8222-222222222222/approved-bucket": {
    manifest_bucket: "existing-reports", manifest_key: "reports/manifest.json",
  } };
  const configured = {
    SCAN_SCHEDULES_MODE: "disabled", SCAN_SQS_MODE: "disabled", SCAN_PUBSUB_MODE: "disabled",
    SCAN_SERVICEBUS_MODE: "disabled", SCAN_CHANGE_FEEDS_MODE: "disabled",
    SCAN_SQS_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/123456789012/cremore-dedicated",
    SCAN_SQS_PROFILE_ID: "11111111-1111-4111-8111-111111111111", SCAN_SQS_DEDICATED_ACKNOWLEDGED: "true",
    SCAN_INVENTORY_MANIFESTS: JSON.stringify(bindings),
  };
  const result = compose(configured);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, "configured Compose environment must resolve");
  const services = JSON.parse(result.stdout).services;
  for (const component of ["api", "worker"]) {
    for (const [name, value] of Object.entries(configured)) assert.equal(services[component].environment[name], value);
    assert.deepEqual(JSON.parse(services[component].environment.SCAN_INVENTORY_MANIFESTS), bindings);
  }
  assert.ok(!Object.keys(services.web.environment).some(name => name.startsWith("SCAN_")));
  assert.ok(services.api.ports.every(port => port.host_ip === "127.0.0.1"));
  const empty = compose({ SCAN_INVENTORY_MANIFESTS: "" });
  assert.equal(empty.status, 0, "empty inventory input must also use the JSON-object default");
  assert.equal(JSON.parse(empty.stdout).services.worker.environment.SCAN_INVENTORY_MANIFESTS, "{}");
});

for (const [name, values, jsonValues, expected] of [
  ["typed schedule mode", ["scanning.schedulesMode=true"], [], /scanning.schedulesMode must be disabled or enabled/],
  ["typed queue mode", ["scanning.sqs.mode=false"], [], /scanning.sqs.mode must be disabled or enabled/],
  ["typed Pub/Sub mode", ["scanning.pubsub.mode=on"], [], /scanning.pubsub.mode must be disabled or enabled/],
  ["typed Service Bus mode", ["scanning.serviceBus.mode=true"], [], /scanning.serviceBus.mode must be disabled or enabled/],
  ["typed change feed mode", ["scanning.changeFeedsMode=off"], [], /scanning.changeFeedsMode must be disabled or enabled/],
  ["typed queue acknowledgement", [], ['scanning.sqs.dedicatedAcknowledged="true"'], /dedicatedAcknowledged must be a boolean/],
  ["malformed queue profile pin", ["scanning.sqs.profileId=11111111"], [], /scanning.sqs.profileId must be an approved profile UUID/],
  ["non-AWS queue URL", ["scanning.sqs.queueURL=https://untrusted.invalid/queue"], [], /explicit HTTPS AWS queue URL/],
  ["non-map inventory bindings", [], ['scanning.inventoryManifests=[]'], /inventoryManifests must be a map/],
  ["malformed inventory identity", [], ['scanning.inventoryManifests={"bucket":{"manifest_bucket":"reports","manifest_key":"manifest.json"}}'], /keys must be connectionUUID\/bucket/],
  ["missing inventory pointer key", [], ['scanning.inventoryManifests={"22222222-2222-4222-8222-222222222222/bucket":{"manifest_bucket":"reports"}}'], /requires only manifest_bucket and manifest_key/],
]) test(`scanning config rejects ${name}`, () => {
  const result = helm("template", values, jsonValues);
  assert.equal(result.error, undefined, result.error?.message);
  assert.notEqual(result.status, 0, "unsafe or incomplete scan configuration must fail rendering");
  assert.match(result.stdout + result.stderr, expected);
  assert.doesNotMatch(result.stdout, /synthetic-do-not-render/);
});

test("network policy defaults preserve clustered DNS and PostgreSQL ports", () => {
  const output = success(helm("template"));
  for (const component of ["api", "worker", "web"]) {
    const policy = networkPolicy(output, component);
    assert.match(policy, /kubernetes\.io\/metadata\.name: kube-system/);
    assert.match(policy, /k8s-app: kube-dns/);
    assert.match(policy, /protocol: UDP, port: 53/);
    assert.match(policy, /protocol: TCP, port: 53/);
    assert.match(policy, /cidr: "0\.0\.0\.0\/0"/);
    assert.match(policy, /protocol: TCP, port: 443/);
    if (component !== "web") assert.match(policy, /protocol: TCP, port: 5432/);
    else assert.doesNotMatch(policy, /port: 5432/);
  }
});

test("network policy custom DNS, PostgreSQL port and HTTPS list reach every responsible component", () => {
  const output = success(helm("template", [
    "networkPolicy.databasePort=6432",
    "networkPolicy.databaseCIDR=192.0.2.10/32",
    "networkPolicy.httpsCIDR=0.0.0.0/0",
    "networkPolicy.httpsEgressCIDRs[0]=198.51.100.0/24",
    "networkPolicy.httpsEgressCIDRs[1]=203.0.113.0/24",
  ], [
    'networkPolicy.dnsNamespaceSelector={"kubernetes.io/metadata.name":null,"enterprise.example/dns-zone":"shared"}',
    'networkPolicy.dnsPodSelector={"k8s-app":null,"app.kubernetes.io/name":"corporate-dns"}',
  ]));
  for (const component of ["api", "worker", "web"]) {
    const policy = networkPolicy(output, component);
    assert.match(policy, /enterprise\.example\/dns-zone: shared/);
    assert.match(policy, /app\.kubernetes\.io\/name: corporate-dns/);
    assert.doesNotMatch(policy, /k8s-app: kube-dns|kubernetes\.io\/metadata\.name: kube-system/);
    assert.match(policy, /cidr: "198\.51\.100\.0\/24"/);
    assert.match(policy, /cidr: "203\.0\.113\.0\/24"/);
    assert.doesNotMatch(policy, /cidr: "0\.0\.0\.0\/0"/);
    if (component !== "web") {
      assert.match(policy, /protocol: TCP, port: 6432/);
      assert.match(policy, /cidr: "192\.0\.2\.10\/32"/);
      assert.doesNotMatch(policy, /port: 5432/);
    } else assert.doesNotMatch(policy, /port: 6432|192\.0\.2\.10/);
  }
});

for (const [name, jsonValues, expected] of [
  ["empty DNS namespace labels", ['networkPolicy.dnsNamespaceSelector={"kubernetes.io/metadata.name":null}'], /dnsNamespaceSelector must be a non-empty matchLabels map/],
  ["empty DNS pod labels", ['networkPolicy.dnsPodSelector={"k8s-app":null}'], /dnsPodSelector must be a non-empty matchLabels map/],
  ["non-map DNS selector", ['networkPolicy.dnsPodSelector=["dns"]'], /dnsPodSelector must be a non-empty matchLabels map/],
  ["non-string DNS label value", ['networkPolicy.dnsPodSelector={"k8s-app":true}'], /dnsPodSelector labels must have non-empty keys and string values/],
  ["zero database port", ['networkPolicy.databasePort=0'], /databasePort must be an integer from 1 to 65535/],
  ["oversized database port", ['networkPolicy.databasePort=65536'], /databasePort must be an integer from 1 to 65535/],
  ["fractional database port", ['networkPolicy.databasePort=5432.5'], /databasePort must be an integer from 1 to 65535/],
  ["named database port", ['networkPolicy.databasePort="postgresql"'], /databasePort must be an integer from 1 to 65535/],
]) test(`network policy rejects ${name}`, () => {
  const result = helm("template", [], jsonValues);
  assert.equal(result.error, undefined, result.error?.message);
  assert.notEqual(result.status, 0, "unsafe network configuration must fail rendering");
  assert.match(result.stdout + result.stderr, expected);
});

for (const [name, values, expected] of [
  ["auth mode", ["auth.mode=token"], /this chart renders OIDC/],
  ["verification mode", ["config.verificationMode=maybe"], /verificationMode must be disabled or enabled/],
  ["sso discovery mode", ["config.ssoDiscoveryMode=maybe"], /ssoDiscoveryMode must be disabled or enabled/],
  ["learned false-positive mode", ["config.learnedFalsePositivesMode=maybe"],
   /learnedFalsePositivesMode must be disabled or enabled/],
  ["potential access mode", ["config.iamPotentialAccessMode=true"],
   /iamPotentialAccessMode must be disabled or enabled/],
  ["secrets inventory mode", ["config.awsSecretsInventoryMode=on"],
   /awsSecretsInventoryMode must be disabled or enabled/],
  ["usage lookup mode", ["config.awsUsageLookupMode=false"],
   /awsUsageLookupMode must be disabled or enabled/],
  ["malformed principal", ["config.scannerPrincipalArn=arn:aws:iam::123456789012:user/scanner"], /exact IAM role ARN/],
  ["HTTP onboarding template", ["config.onboardingTemplateURL=http://example.com/member.yaml"], /onboardingTemplateURL must be HTTPS/],
  ["zero object cap", ["config.maxObjectSizeMB=0"], /maxObjectSizeMB must be a positive integer/],
]) test(`chart rejects invalid ${name}`, () => {
  const result = helm("template", values);
  assert.equal(result.error, undefined, result.error?.message);
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, expected);
});

// The team Compose path: the same OIDC model as the chart, without Kubernetes.
// Every assertion here covers a way this overlay could publish a dashboard that
// authenticates nobody, or authenticates everybody as one shared admin.
const PUBLIC = "deploy/compose/reverse-proxy/compose.public.yml";
const publicEnv = {
  PUBLIC_HOST: "cremore.example.test", OIDC_ISSUER_URL: "https://idp.example.test",
  OIDC_AUDIENCE: "cremore", OIDC_CLIENT_ID: "cremore", OIDC_CLIENT_SECRET: "synthetic-secret",
  OIDC_COOKIE_SECRET: "c".repeat(43), OIDC_VIEWER_GROUP: "sec-viewers",
  OIDC_ANALYST_GROUP: "sec-analysts", OIDC_REMEDIATOR_GROUP: "sec-remediators",
  OIDC_ADMIN_GROUP: "sec-admins",
};

test("the public overlay switches BOTH the API and the web proxy to OIDC", () => {
  const config = JSON.parse(success(compose(publicEnv, [PUBLIC])));
  // Either one left in local mode is a different failure. The API would accept
  // the shared token from anyone who learns it; the web proxy would attach that
  // token itself, on behalf of an unauthenticated caller.
  assert.equal(config.services.api.environment.AUTH_MODE, "oidc");
  assert.equal(config.services.web.environment.CREMORE_AUTH_MODE, "oidc");
  assert.equal(config.services.api.environment.OIDC_ISSUER_URL, publicEnv.OIDC_ISSUER_URL);
  assert.equal(config.services.api.environment.OIDC_AUDIENCE, publicEnv.OIDC_AUDIENCE);
  for (const [name, group] of [["VIEWER", "sec-viewers"], ["ANALYST", "sec-analysts"],
                               ["REMEDIATOR", "sec-remediators"], ["ADMIN", "sec-admins"]]) {
    assert.equal(config.services.api.environment[`OIDC_${name}_GROUP`], group);
  }
});

test("a shared install does not reach AWS as one person's Identity Center session", () => {
  const services = JSON.parse(success(compose(publicEnv, [PUBLIC]))).services;
  // The sweep runs in the worker and the API only reports the setting, so the
  // lock has to be on both or the dashboard offers what the worker will refuse.
  for (const service of ["api", "worker"]) {
    assert.equal(services[service].environment.AWS_SSO_DISCOVERY_MODE, "disabled", service);
    // Cleared, not merely ignored: flipping AUTH_MODE back to local then fails
    // at startup instead of quietly restoring one shared identity.
    assert.equal(services[service].environment.API_TOKEN, "", service);
  }
  assert.equal(services.web.environment.CREMORE_API_TOKEN, "");
  // The single-operator default keeps it, which is the whole difference.
  const base = JSON.parse(success(compose())).services;
  assert.equal(base.api.environment.AWS_SSO_DISCOVERY_MODE, "enabled");
  assert.notEqual(base.api.environment.API_TOKEN, "");
});

test("the base Compose stays single-operator, so the overlay is what changes it", () => {
  const base = JSON.parse(success(compose())).services;
  assert.equal(base.api.environment.AUTH_MODE, "local");
  assert.equal(base.web.environment.CREMORE_AUTH_MODE, "local");
  assert.equal(base.caddy, undefined);
  assert.equal(base["oauth2-proxy"], undefined);
  // Loopback only: the single-operator install is not reachable off the host.
  for (const service of ["api", "web"]) {
    for (const port of base[service].ports) assert.equal(port.host_ip, "127.0.0.1", service);
  }
});

test("only the TLS terminator is published off the host", () => {
  const services = JSON.parse(success(compose(publicEnv, [PUBLIC]))).services;
  for (const service of ["api", "web"]) {
    // These keep the base file's loopback publishing. In OIDC mode both refuse
    // a request with no bearer, so a shell user on the host gains nothing.
    for (const port of services[service].ports) assert.equal(port.host_ip, "127.0.0.1", service);
  }
  assert.equal(services["oauth2-proxy"].ports, undefined);
  assert.deepEqual([...new Set(services.caddy.ports.map(p => p.published))].sort(), ["443", "80"]);
  assert.ok(services.caddy.ports.every(p => !p.host_ip || p.host_ip === "0.0.0.0"));
});

test("the login proxy hands the user's own bearer through and pins its session cookie", () => {
  const proxy = JSON.parse(success(compose(publicEnv, [PUBLIC]))).services["oauth2-proxy"];
  const args = proxy.command.join(" ");
  // Without this the API sees no identity and the whole path is anonymous.
  assert.match(args, /--pass-authorization-header=true/);
  assert.match(args, /--upstream=http:\/\/web:3000/);
  assert.match(args, new RegExp(`--redirect-url=https://${publicEnv.PUBLIC_HOST}/oauth2/callback`));
  for (const flag of ["--cookie-secure=true", "--cookie-httponly=true", "--cookie-samesite=lax",
                      "--cookie-name=__Host-cremore_session", "--cookie-csrf-per-request=true"]) {
    assert.ok(args.includes(flag), flag);
  }
  assert.equal(proxy.environment.OAUTH2_PROXY_CLIENT_SECRET, publicEnv.OIDC_CLIENT_SECRET);
  assert.equal(proxy.read_only, true);
});

for (const missing of ["PUBLIC_HOST", "OIDC_ISSUER_URL", "OIDC_AUDIENCE", "OIDC_CLIENT_ID",
                       "OIDC_CLIENT_SECRET", "OIDC_COOKIE_SECRET"]) {
  test(`the public overlay refuses to start without ${missing}`, () => {
    // Starting anyway would publish a dashboard in a weaker mode than the
    // operator asked for, which is the one outcome worth failing loudly on.
    const result = compose({ ...publicEnv, [missing]: undefined }, [PUBLIC]);
    assert.equal(result.error, undefined, result.error?.message);
    assert.notEqual(result.status, 0, `missing ${missing} still rendered`);
    assert.match(result.stderr + result.stdout, new RegExp(missing));
  });
}

// -- where the sealing master comes from ---------------------------------------
// The master that seals stored connection credentials can stay derived from the
// fingerprint key, be split off into its own key, or live in AWS KMS so only a
// ciphertext is held here. What matters in the rendered deployment is that the
// default changes nothing and that no master is ever written as a plain value.

const CMK = "arn:aws:kms:ap-northeast-2:123456789012:key/2f7c5e1a-0000-4000-8000-0123456789ab";
const CIPHERTEXT = "AQIDAHhBLONGBASE64CIPHERTEXTBLOB0000000000000000000000000000000000=";

test("an installation that sets nothing keeps deriving the sealing master as before", () => {
  const services = JSON.parse(success(compose())).services;
  for (const name of ["api", "worker"]) {
    for (const variable of ["SEALING_KEY", "SEALING_KEY_PREVIOUS", "SEALING_KMS_KEY_ID",
                            "SEALING_KEY_CIPHERTEXT", "SEALING_KEY_CIPHERTEXT_PREVIOUS"]) {
      assert.equal(services[name].environment[variable], "", `${name} ${variable}`);
    }
    assert.notEqual(services[name].environment.FINGERPRINT_KEY, "");
  }
});

test("Compose carries the KMS-held master to both processes that open credentials", () => {
  // The worker is what actually opens a stored credential at scan time, so a
  // setting that reached only the API would seal what could never be unsealed.
  const services = JSON.parse(success(compose({
    SEALING_KMS_KEY_ID: CMK, SEALING_KEY_CIPHERTEXT: CIPHERTEXT,
    SEALING_KEY_CIPHERTEXT_PREVIOUS: "b2xk", SEALING_KEY: "0".repeat(64),
  }))).services;
  for (const name of ["api", "worker"]) {
    assert.equal(services[name].environment.SEALING_KMS_KEY_ID, CMK, name);
    assert.equal(services[name].environment.SEALING_KEY_CIPHERTEXT, CIPHERTEXT, name);
    assert.equal(services[name].environment.SEALING_KEY_CIPHERTEXT_PREVIOUS, "b2xk", name);
    assert.equal(services[name].environment.SEALING_KEY, "0".repeat(64), name);
  }
  // The browser never gets any of it.
  assert.equal(services.web.environment.SEALING_KEY, undefined);
  assert.equal(services.web.environment.SEALING_KEY_CIPHERTEXT, undefined);
});

test("the chart renders no sealing settings until one is asked for", () => {
  const output = success(helm("template"));
  assert.doesNotMatch(output, /SEALING_/, "an upgrade adds no sealing configuration of its own");
});

test("the chart puts the KMS ciphertext in the pod and keeps a hex master in the Secret", () => {
  const output = success(helm("template", [
    `config.sealing.kmsKeyId=${CMK}`,
    `config.sealing.keyCiphertext=${CIPHERTEXT}`,
    "applicationSecret.sealingKey=sealing-key",
    "applicationSecret.sealingKeyPrevious=sealing-key-previous",
  ]));
  for (const component of ["api", "worker"]) {
    const doc = deployment(output, component);
    assert.equal(envValue(doc, "SEALING_KMS_KEY_ID"), CMK, component);
    assert.equal(envValue(doc, "SEALING_KEY_CIPHERTEXT"), CIPHERTEXT, component);
    // The ciphertext is safe as a plain value; the master itself never is.
    assert.match(doc, /name: SEALING_KEY\n\s+valueFrom: \{ secretKeyRef: .*key: sealing-key \}/);
    assert.match(doc, /name: SEALING_KEY_PREVIOUS\n\s+valueFrom: \{ secretKeyRef: .*key: sealing-key-previous \}/);
    assert.doesNotMatch(doc, /name: SEALING_KEY, value:/, `${component} must not inline the master`);
  }
  // The dashboard process has no business holding any of it.
  assert.doesNotMatch(deployment(output, "web"), /SEALING_/);
});

test("the audit trail's MAC key comes from the Secret, to the API and worker only", () => {
  // Without a key named, both processes derive it from the fingerprint key.
  assert.doesNotMatch(success(helm("template")), /AUDIT_CHAIN_KEY/);
  const output = success(helm("template", ["applicationSecret.auditChainKey=audit-chain-key"]));
  for (const component of ["api", "worker"]) {
    const doc = deployment(output, component);
    assert.match(doc, /name: AUDIT_CHAIN_KEY\n\s+valueFrom: \{ secretKeyRef: .*key: audit-chain-key \}/, component);
    assert.doesNotMatch(doc, /name: AUDIT_CHAIN_KEY, value:/, `${component} must not inline the key`);
  }
  assert.doesNotMatch(deployment(output, "web"), /AUDIT_CHAIN_KEY/);
});

const VAULT_PATH = "cremore/sealing-key";

test("a sealing path in Vault reaches the API too, since the API is what seals", () => {
  // The worker opens a stored credential and the API seals a new one. A store
  // wired into only one of them seals what could never be unsealed, or refuses
  // to store anything at all.
  const output = success(helm("template", [
    "secretStore.enabled=true", "secretStore.secretName=cremore-vault",
    `config.sealing.vaultPath=${VAULT_PATH}`,
    "secretStore.sealingTokenKey=sealing-token",
  ]));
  for (const component of ["api", "worker"]) {
    const doc = deployment(output, component);
    assert.equal(envValue(doc, "SEALING_KEY_VAULT_PATH"), VAULT_PATH, component);
    assert.equal(envValue(doc, "SEALING_KEY_VAULT_FIELD"), "key", component);
    assert.match(doc, /name: SECRET_STORE_URL/, component);
  }
  // The API logs in with its own key, whose policy need only read that path;
  // the worker keeps the wider one that reads connection references.
  assert.match(deployment(output, "api"), /key: sealing-token \}/);
  assert.match(deployment(output, "worker"), /key: token \}/);
  assert.doesNotMatch(deployment(output, "web"), /SECRET_STORE|SEALING_/);
});

test("without a sealing path the API is still kept out of the secret store", () => {
  const output = success(helm("template", ["secretStore.enabled=true", "secretStore.secretName=cremore-vault"]));
  assert.doesNotMatch(deployment(output, "api"), /SECRET_STORE/,
    "the API resolves no references, so it gets no store access");
  assert.match(deployment(output, "worker"), /name: SECRET_STORE_URL/);
});

test("Kubernetes workload auth gives the API its own role and projected token", () => {
  const output = success(helm("template", [
    "secretStore.enabled=true", "secretStore.secretName=cremore-vault",
    "secretStore.authMode=kubernetes", "secretStore.kubernetes.role=cremore-worker",
    "secretStore.kubernetes.sealingRole=cremore-sealing",
    `config.sealing.vaultPath=${VAULT_PATH}`,
  ]));
  assert.equal(envValue(deployment(output, "api"), "SECRET_STORE_KUBERNETES_ROLE"), "cremore-sealing");
  assert.equal(envValue(deployment(output, "worker"), "SECRET_STORE_KUBERNETES_ROLE"), "cremore-worker");
  for (const component of ["api", "worker"]) {
    // No projected token means the login has nothing to present.
    assert.match(deployment(output, component), /name: vault-workload-token/, component);
  }
});

for (const [values, message] of [
  [[`config.sealing.vaultPath=${VAULT_PATH}`], /requires secretStore.enabled/],
  [["secretStore.enabled=true", "secretStore.secretName=v", `config.sealing.vaultPath=${VAULT_PATH}`,
    "config.sealing.vaultField="], /vaultField must name the field/],
  [["config.sealing.kmsKeyId=arn:aws:kms:eu-west-1:123456789012:key/x"], /needs keyCiphertext/],
  [["config.sealing.keyCiphertext=AQIDAHg="], /requires kmsKeyId/],
]) {
  test(`the chart refuses a half-configured sealing root (${values[values.length - 1]})`, () => {
    // Rendering anyway leaves an installation that boots and then cannot store
    // the first credential anyone types in.
    const result = helm("template", values);
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr + result.stdout, message);
  });
}

test("Compose carries the Vault-held master to both processes, each with its own token", () => {
  const services = JSON.parse(success(compose({
    SEALING_KEY_VAULT_PATH: VAULT_PATH, SEALING_KEY_VAULT_PATH_PREVIOUS: "cremore/sealing-key-2024",
    SECRET_STORE_URL: "https://vault.internal", SECRET_STORE_TOKEN: "worker-token",
    SEALING_VAULT_TOKEN: "sealing-token",
  }))).services;
  for (const name of ["api", "worker"]) {
    assert.equal(services[name].environment.SEALING_KEY_VAULT_PATH, VAULT_PATH, name);
    assert.equal(services[name].environment.SEALING_KEY_VAULT_PATH_PREVIOUS, "cremore/sealing-key-2024", name);
    assert.equal(services[name].environment.SECRET_STORE_URL, "https://vault.internal", name);
    assert.equal(services[name].environment.SEALING_KEY_VAULT_FIELD, "key", name);
  }
  assert.equal(services.api.environment.SECRET_STORE_TOKEN, "sealing-token");
  assert.equal(services.worker.environment.SECRET_STORE_TOKEN, "worker-token");
  assert.equal(services.web.environment.SECRET_STORE_TOKEN, undefined);
});

test("a key exported into the shell beats one written in .env", () => {
  // This is what lets an operator keep the sealing master in the OS keychain
  // instead of a file: `security find-generic-password` (or DPAPI, or
  // secret-tool) fills the variable for one `docker compose up`, and nothing
  // is written to disk. If Compose ever preferred the file, that would silently
  // go back to sealing under whatever .env holds.
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "cremore-sealing-precedence-"));
  const onDisk = path.join(tempDir, "test.env");
  writeFileSync(onDisk, `SEALING_KEY=${"a".repeat(64)}${os.EOL}`, "utf8");
  try {
    const fromFile = JSON.parse(success(compose({}, [], onDisk))).services.api.environment.SEALING_KEY;
    assert.equal(fromFile, "a".repeat(64), "the file is used when nothing is exported");
    const exported = JSON.parse(success(compose({ SEALING_KEY: "b".repeat(64) }, [], onDisk)))
      .services.api.environment.SEALING_KEY;
    assert.equal(exported, "b".repeat(64), "an exported value wins over the file");
  } finally {
    rmSync(onDisk, { force: true });
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("a typed sealing passphrase reaches both processes that open credentials", () => {
  // It is never written into .env: it is typed and exported for one start. The
  // worker opens stored credentials at scan time, so a value that reached only
  // the API would seal what could never be unsealed.
  const services = JSON.parse(success(compose({ SEALING_PASSPHRASE: "correct horse battery staple" }))).services;
  for (const name of ["api", "worker"]) {
    assert.equal(services[name].environment.SEALING_PASSPHRASE, "correct horse battery staple", name);
  }
  // The browser never gets it.
  assert.equal(services.web.environment.SEALING_PASSPHRASE, undefined);
  // And nothing is set when nobody typed one.
  const quiet = JSON.parse(success(compose())).services;
  assert.equal(quiet.api.environment.SEALING_PASSPHRASE, "");
});

test("a dashboard token exported per start reaches all three services, and no file needs it", () => {
  // API_ADMIN_TOKEN has no rotation path, so an installation that writes it
  // into .env keeps it forever. Compose prefers the shell, and one value feeds
  // api, worker and web -- so it can be generated fresh per start and never
  // written down. That only holds while all three read the same variable.
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "cremore-token-per-start-"));
  const onDisk = path.join(tempDir, "test.env");
  writeFileSync(onDisk, [`POSTGRES_PASSWORD=${"0".repeat(32)}`, `FINGERPRINT_KEY=${"0".repeat(64)}`, ""].join(os.EOL), "utf8");
  try {
    const refused = compose({ API_ADMIN_TOKEN: undefined }, [], onDisk);
    assert.notEqual(refused.status, 0, "a missing token must stop the deployment, not start it unauthenticated");
    assert.match(refused.stderr + refused.stdout, /API_ADMIN_TOKEN/);

    const exported = "b".repeat(40);
    const services = JSON.parse(success(compose({ API_ADMIN_TOKEN: exported }, [], onDisk))).services;
    assert.equal(services.api.environment.API_TOKEN, exported);
    assert.equal(services.worker.environment.API_TOKEN, exported);
    assert.equal(services.web.environment.CREMORE_API_TOKEN, exported);
  } finally {
    rmSync(onDisk, { force: true });
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// -- SIEM exporter ------------------------------------------------------------
// The exporter reads only the SIEM outbox with its own role. What the rendered
// workload must show: nothing until asked for, then an always-on process with
// no scanner secret, a liveness check, and egress to the destinations only.

const SIEM_CONFIG = JSON.stringify({ destinations: [{ id: "soc", provider: "splunk_hec", options: {
  endpoint: "https://splunk.example.test:8088/services/collector/event", token_env: "SPLUNK_HEC_TOKEN" } }] });
const siemDoc = (output, kind) => output.split(/^---\s*$/m).find(doc =>
  new RegExp(`^kind: ${kind}$`, "m").test(doc) && /^  name: .*-siem$/m.test(doc));

test("the SIEM exporter is not rendered until it is enabled", () => {
  const output = success(helm("template"));
  assert.equal(siemDoc(output, "Deployment"), undefined);
  assert.equal(siemDoc(output, "ConfigMap"), undefined);
});

test("an enabled SIEM exporter runs always-on with its own role and no scanner secret", () => {
  const output = success(helm("template", ["siem.enabled=true", "siem.tokenSecretName=siem-tokens"],
    [`siem.config=${SIEM_CONFIG}`, "siem.egressPorts=[8088]"]));
  const deploy = siemDoc(output, "Deployment");
  assert.ok(deploy, "siem deployment rendered");
  assert.match(deploy, /command: \["cremore-siem", "--config", "\/run\/cremore-siem\/siem.json"\]/);
  assert.match(deploy, /name: SIEM_DATABASE_URL\n\s+valueFrom: \{ secretKeyRef: \{ name: "cremore-siem-database", key: "url" \} \}/);
  assert.match(deploy, /secretRef: \{ name: "siem-tokens" \}/);
  assert.match(deploy, /readOnlyRootFilesystem: true/);
  assert.match(deploy, /automountServiceAccountToken: false/);
  assert.match(deploy, /livenessProbe:[\s\S]*cremore-siem\.heartbeat/);
  assert.match(deploy, /checksum\/config: [0-9a-f]{64}/);
  const scannerFree = deploy.replaceAll("SIEM_DATABASE_URL", "SIEM_OWN_ROLE");
  for (const secret of ["FINGERPRINT_KEY", "DATABASE_URL", "SEALING_KEY", "SECRET_STORE", "API_TOKEN"]) {
    assert.doesNotMatch(scannerFree, new RegExp(`name: ${secret}(?![A-Z_])`), secret);
  }
  const config = siemDoc(output, "ConfigMap");
  assert.match(config, /splunk\.example\.test:8088/);
  assert.doesNotMatch(config, /synthetic-token/);
  const policy = siemDoc(output, "NetworkPolicy");
  assert.ok(policy, "siem network policy rendered");
  assert.match(policy, /port: 8088/);
  assert.doesNotMatch(policy, /^  ingress:/m);
});

for (const [name, values, jsonValues, message] of [
  ["no destinations", ["siem.enabled=true"], [], /siem.config.destinations/],
  ["an out-of-range port", ["siem.enabled=true"], [`siem.config=${SIEM_CONFIG}`, "siem.egressPorts=[70000]"], /siem.egressPorts/],
  ["no ports", ["siem.enabled=true"], [`siem.config=${SIEM_CONFIG}`, "siem.egressPorts=[]"], /siem.egressPorts/],
]) test(`an enabled SIEM exporter rejects ${name}`, () => {
  const result = helm("template", values, jsonValues);
  assert.notEqual(result.status, 0, "rendered anyway");
  assert.match(result.stderr, message);
});

const SIEM_OVERRIDE = "deploy/compose/siem/compose.yml";
const siemEnv = { SIEM_DATABASE_URL: "postgresql+psycopg://cremore_siem@db:5432/cremore",
  SIEM_CONFIG_PATH: path.join(chart, "..", "siem", "jsonl.example.json") };

test("the Compose SIEM file runs the exporter hardened and restarting, with only its own settings", () => {
  const siem = JSON.parse(success(compose({ ...publicEnv, ...siemEnv }, [PUBLIC, SIEM_OVERRIDE]))).services.siem;
  assert.equal(siem.restart, "unless-stopped");
  assert.equal(siem.read_only, true);
  assert.ok(siem.security_opt.includes("no-new-privileges:true"));
  assert.equal(siem.ports, undefined);
  assert.equal(siem.environment.SIEM_HEARTBEAT_FILE, "/tmp/cremore-siem.heartbeat");
  for (const name of ["DATABASE_URL", "FINGERPRINT_KEY", "API_TOKEN", "SEALING_KEY"]) {
    assert.equal(siem.environment[name], undefined, name);
  }
  assert.equal(siem.volumes[0].read_only, true);
});

for (const missing of ["SIEM_DATABASE_URL", "SIEM_CONFIG_PATH"]) {
  test(`the Compose SIEM file refuses to start without ${missing}`, () => {
    const result = compose({ ...siemEnv, [missing]: undefined }, [SIEM_OVERRIDE]);
    assert.notEqual(result.status, 0, `missing ${missing} still rendered`);
    assert.match(result.stderr + result.stdout, new RegExp(missing));
  });
}

test("the Compose SIEM file mounts destination certificates read-only", () => {
  const siem = JSON.parse(success(compose({ ...siemEnv }, [SIEM_OVERRIDE]))).services.siem;
  const tls = siem.volumes.find(volume => volume.target === "/etc/cremore-siem");
  assert.ok(tls, "certificate directory mounted");
  assert.equal(tls.read_only, true);
  assert.match(tls.source.replaceAll("\\", "/"), /deploy\/compose\/siem\/tls$/);
  for (const name of ["SENTINEL_CLIENT_SECRET", "ELASTIC_API_KEY", "DD_API_KEY", "OCSF_GATEWAY_TOKEN"]) {
    assert.ok(name in siem.environment, name);
  }
});

test("a SIEM certificate Secret reaches only the exporter", () => {
  const output = success(helm("template", ["siem.enabled=true", "siem.tlsSecretName=siem-tls"], [`siem.config=${SIEM_CONFIG}`]));
  const deploy = siemDoc(output, "Deployment");
  assert.match(deploy, /name: destination-tls, mountPath: \/etc\/cremore-siem, readOnly: true/);
  assert.match(deploy, /secretName: "siem-tls"/);
  assert.doesNotMatch(deployment(output, "worker"), /siem-tls/);
});

const AZURE_CLIENT = "11111111-2222-3333-4444-555555555555";
const serviceAccount = (output, component) => output.split(/^---\s*$/m).find(doc =>
  /^kind: ServiceAccount$/m.test(doc) && new RegExp(`^  name: .*-${component}$`, "m").test(doc));

test("Azure workload identity labels the API and worker pods and annotates their accounts", () => {
  const output = success(helm("template", ["azure.workloadIdentity.enabled=true",
    `azure.workloadIdentity.clientId=${AZURE_CLIENT}`, `azure.workloadIdentity.tenantId=${AZURE_CLIENT.replace("1111", "9999")}`,
    "serviceAccounts.worker.annotations.team=platform"]));
  for (const component of ["api", "worker"]) {
    const doc = deployment(output, component);
    assert.match(doc, /template:\n    metadata:\n      labels: \n[\s\S]*?azure\.workload\.identity\/use: "true"/);
    assert.match(doc, /azure\.workload\.identity\/service-account-token-expiration: "3600"/);
    const account = serviceAccount(output, component);
    assert.match(account, new RegExp(`azure\\.workload\\.identity/client-id: ${AZURE_CLIENT}`));
    assert.match(account, /azure\.workload\.identity\/tenant-id: 99991111-/);
    // The selector stays as it was: labels a Deployment cannot change later.
    assert.doesNotMatch(doc.split("template:")[0], /azure\.workload\.identity/);
  }
  assert.match(serviceAccount(output, "worker"), /team: platform/);
  assert.doesNotMatch(deployment(output, "web"), /azure\.workload\.identity/);
  assert.doesNotMatch(serviceAccount(output, "web"), /azure\.workload\.identity/);
  assert.doesNotMatch(success(helm("template")), /azure\.workload\.identity/);
});

for (const [name, values, message] of [
  ["no client ID", ["azure.workloadIdentity.enabled=true"], /clientId must be the Entra application/],
  ["a short token life", ["azure.workloadIdentity.enabled=true", `azure.workloadIdentity.clientId=${AZURE_CLIENT}`,
    "azure.workloadIdentity.tokenExpirationSeconds=600"], /tokenExpirationSeconds must be an integer from 3600/],
]) test(`Azure workload identity rejects ${name}`, () => {
  const result = helm("template", values);
  assert.notEqual(result.status, 0, "rendered anyway");
  assert.match(result.stderr, message);
});

test("each external Vault cluster gets its own audience-bound token in the worker only", () => {
  const output = success(helm("template", [], [
    'vaultConnections.tokens=[{"name":"vault-pay","audience":"vault-pay"},{"name":"bao-ci","audience":"https://bao.example"}]',
    'vaultConnections.egress=[{"cidr":"10.20.0.0/16","port":8200}]']));
  const worker = deployment(output, "worker");
  assert.equal(envValue(worker, "VAULT_CONNECTION_TOKEN_DIR"), "/run/cremore-vault-connections");
  assert.match(worker, /name: vault-connection-tokens, mountPath: \/run\/cremore-vault-connections, readOnly: true/);
  assert.match(worker, /path: vault-pay\n\s+audience: "vault-pay"\n\s+expirationSeconds: 600/);
  assert.match(worker, /path: bao-ci\n\s+audience: "https:\/\/bao\.example"/);
  assert.doesNotMatch(deployment(output, "api"), /vault-connection|VAULT_CONNECTION/);
  const workerPolicy = output.split(/^---\s*$/m).find(doc => /^kind: NetworkPolicy$/m.test(doc) && /^  name: .*-worker$/m.test(doc));
  assert.match(workerPolicy, /cidr: "10\.20\.0\.0\/16"[\s\S]*port: 8200/);
});

test("owner contact reaches the company's SMTP relay from the API only when it is listed", () => {
  const policy = (output, component) => output.split(/^---\s*$/m).find(doc => /^kind: NetworkPolicy$/m.test(doc)
    && new RegExp(`^  name: .*-${component}$`, "m").test(doc));
  const plain = success(helm("template", ["networkPolicy.enabled=true"]));
  assert.doesNotMatch(policy(plain, "api"), /port: 587/);
  const output = success(helm("template", ["networkPolicy.enabled=true"], ['contactDelivery.smtpEgress=[{"cidr":"10.30.0.25/32","port":587}]']));
  assert.match(policy(output, "api"), /cidr: "10\.30\.0\.25\/32"[\s\S]*port: 587/);
  assert.doesNotMatch(policy(output, "worker"), /10\.30\.0\.25/);
});

for (const [name, json, message] of [
  ["a path as a name", 'vaultConnections.tokens=[{"name":"../x","audience":"a"}]', /must be a file name/],
  ["a repeated name", 'vaultConnections.tokens=[{"name":"a","audience":"a"},{"name":"a","audience":"b"}]', /must be unique/],
  ["no audience", 'vaultConnections.tokens=[{"name":"a"}]', /audience is required/],
]) test(`Vault connection tokens reject ${name}`, () => {
  const result = helm("template", [], [json]);
  assert.notEqual(result.status, 0, "rendered anyway");
  assert.match(result.stderr, message);
});

const IDENTITY = "deploy/compose/identity";
const identityEnv = { IDENTITY_REFRESHER_CONFIG: path.join(chart, "..", "compose", "identity", "refresher.example.json"),
  AWS_ROLE_ARN: "arn:aws:iam::123456789012:role/CreMoreWorkload", AZURE_CLIENT_ID: AZURE_CLIENT, AZURE_TENANT_ID: AZURE_CLIENT,
  GCP_WIF_CONFIG: path.join(chart, "..", "compose", "identity", "refresher.example.json") };

test("the token refresher shares tokens read-only with the API and worker", () => {
  const services = JSON.parse(success(compose(identityEnv, [`${IDENTITY}/refresher.yml`, `${IDENTITY}/aws-web-identity.yml`,
    `${IDENTITY}/azure-workload-identity.yml`, `${IDENTITY}/gcp-workload-identity.yml`]))).services;
  const refresher = services["identity-refresher"];
  assert.deepEqual(refresher.command, ["cremore-token-refresher", "--config", "/run/cremore/refresher.json"]);
  assert.equal(refresher.read_only, true);
  assert.ok(refresher.security_opt.includes("no-new-privileges:true"));
  assert.equal(refresher.environment.FINGERPRINT_KEY, undefined);
  const writable = refresher.volumes.find(volume => volume.target === "/run/cremore-identity");
  assert.notEqual(writable.read_only, true);
  for (const name of ["api", "worker"]) {
    const mount = services[name].volumes.find(volume => volume.target === "/run/cremore-identity");
    assert.equal(mount.read_only, true, name);
    assert.equal(services[name].environment.AWS_ROLE_ARN, identityEnv.AWS_ROLE_ARN);
    assert.equal(services[name].environment.AWS_WEB_IDENTITY_TOKEN_FILE, "/run/cremore-identity/cloud/aws");
    assert.equal(services[name].environment.AWS_EC2_METADATA_DISABLED, "true");
    assert.equal(services[name].environment.AZURE_FEDERATED_TOKEN_FILE, "/run/cremore-identity/cloud/azure");
  }
  assert.equal(services.worker.environment.VAULT_CONNECTION_TOKEN_DIR, "/run/cremore-identity/vault");
  assert.equal(services.worker.environment.GOOGLE_APPLICATION_CREDENTIALS, "/run/gcp/wif.json");
  assert.equal(services.api.environment.GOOGLE_APPLICATION_CREDENTIALS, undefined);
});

for (const [file, missing] of [["refresher.yml", "IDENTITY_REFRESHER_CONFIG"], ["aws-web-identity.yml", "AWS_ROLE_ARN"],
  ["azure-workload-identity.yml", "AZURE_CLIENT_ID"], ["gcp-workload-identity.yml", "GCP_WIF_CONFIG"]]) {
  test(`the ${file} identity file refuses to start without ${missing}`, () => {
    const result = compose({ ...identityEnv, [missing]: undefined }, [`${IDENTITY}/${file}`]);
    assert.notEqual(result.status, 0, `missing ${missing} still rendered`);
    assert.match(result.stderr + result.stdout, new RegExp(missing));
  });
}

test("heartbeat and SIEM retention reach the API and worker in both deployments", () => {
  const output = success(helm("template", ["config.operations.heartbeatMinutes=1", "config.operations.siemEventRetentionDays=30",
    "config.operations.leaverRetentionDays=180"]));
  for (const component of ["api", "worker"]) {
    assert.equal(envValue(deployment(output, component), "OPERATIONS_HEARTBEAT_MINUTES"), "1");
    assert.equal(envValue(deployment(output, component), "SIEM_EVENT_RETENTION_DAYS"), "30");
    assert.equal(envValue(deployment(output, component), "LEAVER_RETENTION_DAYS"), "180");
  }
  const short = helm("template", ["config.operations.leaverRetentionDays=7"]);
  assert.notEqual(short.status, 0);
  assert.match(short.stderr, /leaverRetentionDays must be an integer from 30 to 3650/);
  const refused = helm("template", ["config.operations.heartbeatMinutes=0"]);
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /heartbeatMinutes must be an integer from 1 to 60/);
  const services = JSON.parse(success(compose({ OPERATIONS_HEARTBEAT_MINUTES: "2" }))).services;
  assert.equal(services.worker.environment.OPERATIONS_HEARTBEAT_MINUTES, "2");
  assert.equal(services.api.environment.SIEM_EVENT_RETENTION_DAYS, "0");
  assert.equal(services.worker.environment.LEAVER_RETENTION_DAYS, "365");
});

test("task-runner concurrency reaches only the scanning worker in both deployments", () => {
  assert.equal(envValue(deployment(success(helm("template")), "worker"), "WORKER_CONCURRENCY"), "2");
  const output = success(helm("template", ["config.workerConcurrency=3"]));
  assert.equal(envValue(deployment(output, "worker"), "WORKER_CONCURRENCY"), "3");
  for (const component of ["api", "web"]) assert.doesNotMatch(deployment(output, component), /WORKER_CONCURRENCY/);
  const refused = helm("template", ["config.workerConcurrency=33"]);
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /workerConcurrency must be an integer from 0 to 32/);
  const defaults = JSON.parse(success(compose())).services;
  assert.equal(defaults.worker.environment.WORKER_CONCURRENCY, "0");
  const services = JSON.parse(success(compose({ WORKER_CONCURRENCY: "6" }))).services;
  assert.equal(services.worker.environment.WORKER_CONCURRENCY, "6");
  assert.equal(services.api.environment.WORKER_CONCURRENCY, undefined);
  // Orphaned document-parser children are reaped: an init in Compose; in Kubernetes the pod's pause process, opt-in.
  assert.equal(defaults.worker.init, true);
  assert.equal(defaults.worker.stop_grace_period, "30s");
  assert.doesNotMatch(output, /shareProcessNamespace/);
  const shared = success(helm("template", ["workerPod.shareProcessNamespace=true"]));
  assert.match(deployment(shared, "worker"), /^      shareProcessNamespace: true$/m);
  for (const component of ["api", "web"]) assert.doesNotMatch(deployment(shared, component), /shareProcessNamespace/);
  const typed = helm("template", ["workerPod.shareProcessNamespace=yes"]);
  assert.notEqual(typed.status, 0);
  assert.match(typed.stderr, /workerPod.shareProcessNamespace must be a boolean/);
  // Memory for the control loop and two scanning runners, each with read-ahead and a parser child, with headroom.
  const worker = deployment(output, "worker");
  assert.match(worker, /limits:\s+cpu: "2"\s+memory: 3Gi/);
  assert.match(worker, /requests:\s+cpu: 250m\s+memory: 512Mi/);
});

const { prepareRelease } = require("../release.cjs");
function releaseFixture(callback) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "cremore-release-test-"));
  const artifacts = path.join(dir, "artifacts"), destination = path.join(dir, "dist");
  const repository = "Example/CreMore", sha = "a".repeat(40);
  const records = {};
  for (const [index, component] of ["api", "worker", "web", "oauth2-proxy"].entries()) {
    const folder = path.join(artifacts, `release-image-${component}`);
    mkdirSync(folder, { recursive: true });
    records[component] = { component, image: `ghcr.io/example/cremore-${component}`, digest: `sha256:${String(index + 1).repeat(64)}`, sha };
    writeFileSync(path.join(folder, `${component}.json`), JSON.stringify(records[component]));
  }
  try { callback({ dir, artifacts, destination, repository, sha, records,
    prepare: () => prepareRelease(repository, sha, artifacts, chart, destination) }); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

test("release chart and Compose run the signed component digests without local builds", () => {
  releaseFixture(({ destination, repository, sha, prepare }) => {
    const original = readFileSync(path.join(chart, "values.yaml"), "utf8");
    const { images, stagedChart } = prepare();
    assert.equal(readFileSync(path.join(chart, "values.yaml"), "utf8"), original, "development defaults remain unchanged");
    assert.deepEqual(JSON.parse(readFileSync(path.join(destination, "release-images.json"), "utf8")), { repository, sha, images });
    success(helm("lint", [], [], stagedChart));
    const packageArgs = nativeHelm ? ["package", stagedChart] : ["run", "--rm", "--network", "none", "--pull", "never",
      "-v", `${stagedChart}:/chart:ro`, "-v", `${destination}:/dist`, image, "package", "/chart"];
    packageArgs.push("--version", "1.2.3", "--app-version", "1.2.3", "--destination", nativeHelm ? destination : "/dist");
    success(spawnSync(nativeHelm || "docker", packageArgs, { encoding: "utf8", timeout: 60000 }));
    const packaged = path.join(destination, "cremore-1.2.3.tgz");
    const output = success(helm("template", [], [], packaged));
    for (const component of ["api", "worker", "web"]) {
      assert.ok(deployment(output, component).includes(`image: "${images[component]}"`));
    }
    assert.ok(deployment(output, "web").includes(`image: "${images["oauth2-proxy"]}"`));
    const override = path.join(destination, "compose.release.yml");
    const missingCaddy = compose(publicEnv, [PUBLIC, override]);
    assert.notEqual(missingCaddy.status, 0);
    assert.match(missingCaddy.stderr, /CREMORE_CADDY_SHA256/);
    const releaseEnv = { ...publicEnv, CREMORE_CADDY_SHA256: "c".repeat(64) };
    const services = JSON.parse(success(compose(releaseEnv, [PUBLIC, override]))).services;
    for (const [component, ref] of Object.entries(images)) {
      assert.equal(services[component].image, ref);
      assert.equal(services[component].build, undefined, "no local build can replace the signed image");
      assert.equal(services[component].pull_policy, "always");
    }
    assert.equal(services.siem, undefined);
    assert.equal(services["identity-refresher"], undefined);
    assert.equal(services.caddy.image, `caddy@sha256:${releaseEnv.CREMORE_CADDY_SHA256}`);
    assert.equal(services.caddy.build, undefined);
    const optional = JSON.parse(success(compose({ ...releaseEnv, ...siemEnv, ...identityEnv }, [
      PUBLIC, SIEM_OVERRIDE, `${IDENTITY}/refresher.yml`, override,
      path.join(destination, "compose.release.siem.yml"), path.join(destination, "compose.release.identity.yml"),
    ]))).services;
    for (const component of ["siem", "identity-refresher"]) {
      assert.equal(optional[component].image, images.worker);
      assert.equal(optional[component].build, undefined);
    }
    for (const setting of ["image.api", "image.worker", "image.web", "auth.oidc.oauth2Proxy.image"]) {
      const result = helm("template", [`${setting}=example/unsigned:latest`], [], packaged);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /image must be pinned to a sha256 digest/);
    }
    const siem = success(helm("template", ["siem.enabled=true"], [`siem.config=${SIEM_CONFIG}`], stagedChart));
    assert.ok(siemDoc(siem, "Deployment").includes(`image: "${images.worker}"`));
    const badSiem = helm("template", ["siem.enabled=true", "siem.image=example/unsigned:latest"], [`siem.config=${SIEM_CONFIG}`], stagedChart);
    assert.notEqual(badSiem.status, 0);
    assert.match(badSiem.stderr, /siem image must be pinned/);
  });
});

for (const [name, mutate] of [
  ["missing component", (record, file) => rmSync(file)],
  ["mutable image tag", record => { record.digest = "latest"; }],
  ["another source commit", record => { record.sha = "b".repeat(40); }],
  ["another repository", record => { record.image = "ghcr.io/other/cremore-api"; }],
  ["another component", record => { record.component = "web"; }],
]) test(`release packaging refuses ${name}`, () => {
  releaseFixture(({ artifacts, records, prepare }) => {
    const file = path.join(artifacts, "release-image-api", "api.json");
    const record = records.api;
    if (name === "missing component") mutate(record, file);
    else { mutate(record, file); writeFileSync(file, JSON.stringify(record)); }
    assert.throws(prepare, /ENOENT|Invalid signed image reference/);
  });
});

test("release packaging refuses chart drift instead of shipping old defaults", () => {
  releaseFixture(({ dir, artifacts, destination, repository, sha }) => {
    const source = path.join(dir, "source");
    cpSync(chart, source, { recursive: true });
    const valuesPath = path.join(source, "values.yaml");
    writeFileSync(valuesPath, readFileSync(valuesPath, "utf8").replace("  api: ghcr.io/", "  renamed: ghcr.io/"));
    assert.throws(() => prepareRelease(repository, sha, artifacts, source, destination), /Expected one chart image setting/);
  });
});

test("PR container scans and the exact release digest gate cannot be skipped before signing", () => {
  const workflows = path.resolve(chart, "../../.github/workflows");
  const ci = readFileSync(path.join(workflows, "ci.yml"), "utf8");
  const containers = ci.slice(ci.indexOf("  containers:"));
  assert.match(ci, /\n  pull_request:/);
  assert.doesNotMatch(containers.split("    steps:")[0], /\n    if:/, "the container job runs on PRs too");
  assert.match(containers, /exit-code: "1"/);
  const release = readFileSync(path.join(workflows, "release.yml"), "utf8");
  const imageJob = release.split("  chart:")[0];
  const scan = imageJob.match(/      - name: Audit release image digest before signing\n([\s\S]*?)(?=      - uses:)/)?.[1];
  assert.ok(scan, "each matrix image is scanned before cosign is installed");
  assert.match(scan, /DIGEST: \$\{\{ steps\.build\.outputs\.digest \}\}/);
  assert.match(scan, /--image-src remote --scanners vuln --severity HIGH,CRITICAL/);
  assert.match(scan, /--exit-code 1 --no-progress "\$IMAGE@\$DIGEST"/);
  assert.doesNotMatch(scan, /\n\s+if:|continue-on-error|ignore-unfixed|\|\| true/);
  assert.doesNotMatch(imageJob, /continue-on-error/);
  const scanner = scan.match(/aquasec\/trivy:[^\s]+/)?.[0];
  assert.ok(scanner?.includes("@sha256:"));
  assert.ok(ci.includes(scanner), "release reuses CI's pinned scanner");
  assert.ok(imageJob.indexOf("Audit release image digest") < imageJob.indexOf("Keyless-sign image digest"));
  assert.ok(imageJob.indexOf("Keyless-sign image digest") < imageJob.indexOf("Record signed release image"));
  assert.match(release, /  chart:\n    needs: images/);
});
