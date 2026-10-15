// Render only: no daemon operation, image pull, network creation or credential use.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const os = require("node:os");
const { readFileSync, writeFileSync, mkdtempSync, unlinkSync, rmdirSync } = require("node:fs");
const { spawnSync } = require("node:child_process");

const directory = path.resolve(__dirname, "..");
const source = readFileSync(path.join(directory, "compose.yml"), "utf8");
const envExample = readFileSync(path.join(directory, ".env.example"), "utf8");
const temporary = mkdtempSync(path.join(os.tmpdir(), "cremore-isolated-render-"));
const emptyEnv = path.join(temporary, "empty.env");
writeFileSync(emptyEnv, "");
test.after(() => { unlinkSync(emptyEnv); rmdirSync(temporary); });

const paths = Object.fromEntries([
  ["DATABASE_CA_PATH", "public/db-ca.pem"],
  ["SEALING_PUBLIC_KEYS_PATH", "public/recipients.json"],
  ["REMEDIATION_APPROVAL_PUBLIC_KEY_PATH", "public/approval-public.pem"],
  ["COLLECTOR_PRIVATE_KEYS_PATH", "collector/private.json"],
  ["REMEDIATOR_PRIVATE_KEYS_PATH", "remediator/private.json"],
  ["COLLECTOR_CLOUD_IDENTITY_DIR", "collector/cloud"],
  ["REMEDIATOR_CLOUD_IDENTITY_DIR", "remediator/cloud"],
  ["TLS_CERT_DIRECTORY", "gateway-tls"],
  ["SIEM_CONFIG_PATH", "siem/destination.json"],
  ["SIEM_TLS_DIR", "siem/tls"],
].map(([name, file]) => [name, path.join(temporary, file)]));
const dbRoles = ["api", "collector", "remediator", "control", "siem", "migration"];
const externalRoles = ["edge", "api", "collector", "remediator", "control", "siem", "oidc", "migration"];
const synthetic = {
  ...paths,
  ...Object.fromEntries(dbRoles.map(role => [`${role.toUpperCase()}_DATABASE_URL`,
    `postgresql+psycopg://cremore_${role}:synthetic-${role}@db.example.test/cremore?sslmode=verify-full&sslrootcert=/run/cremore/database-ca.pem`])),
  ...Object.fromEntries(externalRoles.map(role => [`CREMORE_${role.toUpperCase()}_NETWORK`, `synthetic-${role}-constrained`])),
  ...Object.fromEntries(["PYTHON", "WEB", "OIDC", "CADDY"].flatMap((name, index) => [
    [`CREMORE_${name}_REPOSITORY`, `example.invalid/cremore-${name.toLowerCase()}`],
    [`CREMORE_${name}_SHA256`, String(index + 1).repeat(64)],
  ])),
  FINGERPRINT_KEY: "1".repeat(64), AUDIT_CHAIN_KEY: "2".repeat(64), CONTROL_SEALING_KEY: "3".repeat(64),
  PUBLIC_HOST: "cremore.example.test", PUBLIC_BIND_IP: "127.0.0.1", CREMORE_DNS_SERVER: "192.0.2.53",
  OIDC_ISSUER_URL: "https://idp.example.test", OIDC_AUDIENCE: "cremore", OIDC_CLIENT_ID: "cremore-test",
  OIDC_CLIENT_SECRET: "synthetic-oidc-secret", OIDC_COOKIE_SECRET: "synthetic-cookie-secret",
  OIDC_ADMIN_GROUP: "synthetic-admins", SIEM_DESTINATION_TOKEN: "synthetic-ingest-only-token",
};

function render(overrides = {}) {
  // Preserve only launch/Compose discovery values, never application env or .env.
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    /^(path|systemroot|windir|comspec|temp|tmp|userprofile|appdata|localappdata|programdata|programfiles(?:\(x86\))?|programw6432|homedrive|homepath|home|docker_config)$/i.test(name)));
  const env = { ...inherited, ...synthetic, ...overrides };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  return spawnSync("docker", ["compose", "--env-file", emptyEnv, "-f", path.join(directory, "compose.yml"),
    "--profile", "*", "config", "--format", "json"], { env, encoding: "utf8", timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
}
function success(result) {
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
const rendered = success(render());
const services = rendered.services;
const mounts = service => Object.fromEntries((service.volumes || []).map(volume => [volume.target, volume]));
const ordered = values => [...values].sort();

test("standalone service inventory uses pinned images and never imports legacy configuration", () => {
  assert.deepEqual(ordered(Object.keys(services)), ordered([
    "api", "collector", "remediator", "control", "siem", "migrate", "web", "oauth2-proxy", "gateway",
  ]));
  assert.doesNotMatch(source, /^\s*(include|extends|env_file|build):/m);
  for (const service of Object.values(services)) {
    assert.match(service.image, /@sha256:[a-f0-9]{64}$/);
    assert.equal(service.build, undefined);
    assert.equal(service.env_file, undefined);
  }
  const contaminated = success(render({
    SEALING_KEY: "synthetic-legacy-secret", AWS_ACCESS_KEY_ID: "synthetic-unrelated-aws-id",
    AWS_SECRET_ACCESS_KEY: "synthetic-unrelated-aws-secret", API_ADMIN_TOKEN: "synthetic-legacy-admin",
    DATABASE_URL: "synthetic-shared-db", GOOGLE_APPLICATION_CREDENTIALS: "/host/adc.json",
  }));
  assert.deepEqual(contaminated, rendered, "unreferenced host secrets must not reach services");
});

test("all processes are nonroot, read-only and capability-free with bounded scratch space", () => {
  for (const [name, service] of Object.entries(services)) {
    assert.equal(service.user, "65532:65532", name);
    assert.equal(service.read_only, true, name);
    assert.deepEqual(service.cap_drop, ["ALL"], name);
    assert.ok(service.security_opt.includes("no-new-privileges:true"), name);
    assert.ok(service.tmpfs.some(value => value.startsWith("/tmp:") && value.includes("noexec") && value.includes("size=")), name);
    assert.equal(service.privileged, undefined, name);
    for (const field of ["network_mode", "pid", "ipc", "devices", "cap_add", "extra_hosts"]) assert.equal(service[field], undefined, `${name}.${field}`);
    for (const volume of service.volumes || []) {
      assert.equal(volume.type, "bind", name);
      assert.equal(volume.read_only, true, name);
      assert.equal(volume.bind.create_host_path, false, name);
      assert.doesNotMatch(volume.source, /docker\.sock|[/\\]\.aws(?:[/\\]|$)|[/\\]\.config[/\\]gcloud/);
    }
    if (name !== "gateway") assert.equal(service.ports, undefined, name);
  }
  assert.deepEqual(services.gateway.ports.map(port => [port.host_ip, port.published, port.target, port.protocol]),
    [["127.0.0.1", "443", 8443, "tcp"]]);
});

test("runtime DB logins are distinct and migration credentials never reach a runtime", () => {
  for (const role of dbRoles) {
    const name = role === "migration" ? "migrate" : role;
    const env = services[name].environment;
    const key = role === "siem" ? "SIEM_DATABASE_URL" : "DATABASE_URL";
    assert.equal(env[key], synthetic[`${role.toUpperCase()}_DATABASE_URL`]);
    assert.ok(mounts(services[name])["/run/cremore/database-ca.pem"]);
    for (const other of dbRoles.filter(other => other !== role)) {
      assert.ok(!Object.values(env).includes(synthetic[`${other.toUpperCase()}_DATABASE_URL`]), `${name} inherited ${other}`);
    }
    if (role !== "migration") assert.equal(env.ISOLATED_DEPLOYMENT, "true");
  }
  assert.deepEqual(services.migrate.profiles, ["migration"]);
  assert.equal(services.migrate.restart, "no");
  assert.deepEqual(services.migrate.command, ["python", "-m", "cremore.db.startup"]);
  assert.deepEqual(Object.keys(services.migrate.environment), ["DATABASE_URL"]);
  assert.deepEqual(Object.keys(mounts(services.migrate)), ["/run/cremore/database-ca.pem"]);
});

test("connector private keys and cloud identity directories stay in their own execution role", () => {
  for (const role of ["collector", "remediator", "control"]) {
    assert.equal(services[role].environment.WORKER_EXECUTION_ROLE, role);
    assert.deepEqual(services[role].command, ["cremore-worker"]);
  }
  for (const role of ["collector", "remediator"]) {
    const env = services[role].environment, files = mounts(services[role]);
    assert.equal(env.SEALING_PRIVATE_KEYS_FILE, `/run/cremore/${role}-private.json`);
    assert.equal(path.normalize(files[env.SEALING_PRIVATE_KEYS_FILE].source), path.normalize(paths[`${role.toUpperCase()}_PRIVATE_KEYS_PATH`]));
    assert.equal(path.normalize(files["/run/cloud-identity"].source), path.normalize(paths[`${role.toUpperCase()}_CLOUD_IDENTITY_DIR`]));
    assert.equal(env.CONTROL_SEALING_KEY, undefined);
    assert.equal(env.AWS_SHARED_CREDENTIALS_FILE, "/dev/null");
    assert.equal(env.AWS_CONFIG_FILE, "/run/cloud-identity/aws/config");
    assert.equal(env.GOOGLE_APPLICATION_CREDENTIALS, "/run/cloud-identity/gcp/adc.json");
    assert.equal(env.AZURE_FEDERATED_TOKEN_FILE, "/run/cloud-identity/azure/token");
  }
  for (const role of ["api", "control", "siem", "migrate", "web", "oauth2-proxy", "gateway"]) {
    const env = services[role].environment;
    assert.equal(env.SEALING_PRIVATE_KEYS_FILE, undefined, role);
    for (const name of ["AWS_CONFIG_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLES_ANYWHERE_CONFIG",
      "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE"]) assert.equal(env[name], undefined, `${role}.${name}`);
    assert.equal(mounts(services[role])["/run/cloud-identity"], undefined, role);
  }
  for (const role of ["api", "collector", "remediator", "control"]) {
    assert.equal(services[role].environment.AWS_SSO_DISCOVERY_MODE, "disabled");
    assert.equal(services[role].environment.AWS_EC2_METADATA_DISABLED, "true");
    assert.equal(services[role].environment.FINGERPRINT_KEY, synthetic.FINGERPRINT_KEY);
    assert.equal(services[role].environment.AUDIT_CHAIN_KEY, synthetic.AUDIT_CHAIN_KEY);
  }
  for (const role of ["api", "control"]) assert.equal(services[role].environment.CONTROL_SEALING_KEY, synthetic.CONTROL_SEALING_KEY);
  for (const role of ["siem", "migrate", "web", "oauth2-proxy", "gateway"]) {
    for (const key of ["CONTROL_SEALING_KEY", "FINGERPRINT_KEY", "AUDIT_CHAIN_KEY"]) assert.equal(services[role].environment[key], undefined, role);
  }
});

test("only API and remediator receive an approval public key; no signing key is configured", () => {
  for (const [name, service] of Object.entries(services)) {
    const file = service.environment.REMEDIATION_APPROVAL_PUBLIC_KEY_FILE;
    if (["api", "remediator"].includes(name)) {
      assert.equal(file, "/run/cremore/approval-public.pem");
      assert.ok(mounts(service)[file]);
    } else assert.equal(file, undefined, name);
    assert.ok(!Object.keys(service.environment).some(key => /APPROVAL.*PRIVATE|SIGNING.*KEY/.test(key)), name);
  }
});

test("SIEM keeps its existing exporter and only a destination credential", () => {
  assert.deepEqual(services.siem.command, ["cremore-siem", "--config", "/run/cremore/siem.json"]);
  assert.deepEqual(ordered(Object.keys(services.siem.environment)), ordered([
    "ISOLATED_DEPLOYMENT", "SIEM_DATABASE_URL", "SIEM_HEARTBEAT_FILE", "SIEM_DESTINATION_TOKEN", "SLACK_ALERT_WEBHOOK_URL",
  ]));
  assert.deepEqual(ordered(Object.keys(mounts(services.siem))), ordered([
    "/run/cremore/database-ca.pem", "/run/cremore/siem.json", "/etc/cremore-siem",
  ]));
  for (const [name, service] of Object.entries(services)) {
    if (name !== "siem") assert.equal(service.environment?.SLACK_ALERT_WEBHOOK_URL, undefined, name);
  }
});

test("role egress requires external networks and internal hops have only their intended peers", () => {
  const expected = {
    api: ["api-egress", "web-api"], collector: ["collector-egress"], remediator: ["remediator-egress"],
    control: ["control-egress"], siem: ["siem-egress"], migrate: ["migration-egress"],
    web: ["web-api", "oidc-web"], "oauth2-proxy": ["gateway-oidc", "oidc-web", "oidc-egress"], gateway: ["edge", "gateway-oidc"],
  };
  for (const [name, networks] of Object.entries(expected)) assert.deepEqual(ordered(Object.keys(services[name].networks)), ordered(networks), name);
  assert.equal(rendered.networks.default, undefined);
  for (const role of externalRoles) {
    const network = rendered.networks[role === "edge" ? role : `${role}-egress`];
    assert.equal(network.external, true, role);
    assert.equal(network.name, synthetic[`CREMORE_${role.toUpperCase()}_NETWORK`]);
    assert.equal(network.driver, undefined, "Compose must not create fallback bridges");
  }
  for (const name of ["gateway-oidc", "oidc-web", "web-api"]) assert.equal(rendered.networks[name].internal, true);
});

test("OIDC proxies a per-user bearer and only gateway publishes HTTPS", () => {
  for (const role of ["api", "collector", "remediator", "control"]) {
    assert.equal(services[role].environment.AUTH_MODE, "oidc", role);
    assert.equal(services[role].environment.API_TOKEN, "", role);
    assert.equal(services[role].environment.OIDC_ISSUER_URL, synthetic.OIDC_ISSUER_URL, role);
    assert.equal(services[role].environment.OIDC_ADMIN_GROUP, synthetic.OIDC_ADMIN_GROUP, role);
  }
  assert.equal(services.web.environment.CREMORE_AUTH_MODE, "oidc");
  assert.equal(services.web.environment.CREMORE_API_TOKEN, "");
  assert.equal(services.web.environment.CREMORE_API_URL, "http://api:8080");
  assert.equal(services.web.healthcheck.test[1], "/nodejs/bin/node", "the distroless node binary is outside PATH");
  for (const flag of ["--pass-authorization-header=true", "--upstream=http://web:3000", "--request-logging=false",
    "--cookie-secure=true", "--cookie-httponly=true", "--cookie-name=__Host-cremore_session",
    "--redirect-url=https://cremore.example.test/oauth2/callback"]) assert.ok(services["oauth2-proxy"].command.includes(flag), flag);
  for (const [name, service] of Object.entries(services)) {
    if (name !== "oauth2-proxy") assert.equal(service.environment.OAUTH2_PROXY_CLIENT_SECRET, undefined, name);
  }
  const caddy = readFileSync(path.join(directory, "Caddyfile"), "utf8");
  for (const text of ["admin off", "persist_config off", "auto_https off", "https://{$PUBLIC_HOST}:8443",
    "tls /run/tls/fullchain.pem /run/tls/privkey.pem", "reverse_proxy oauth2-proxy:4180"]) assert.ok(caddy.includes(text), text);
});

test("projected and Roles Anywhere identity settings can be selected separately for each role", () => {
  const configured = success(render({
    COLLECTOR_AWS_ROLE_ARN: "arn:aws:iam::111122223333:role/SyntheticCollector",
    COLLECTOR_AWS_WEB_IDENTITY_TOKEN_FILE: "/run/cloud-identity/aws/token",
    REMEDIATOR_AWS_ROLES_ANYWHERE_CONFIG: "/run/cloud-identity/aws/roles-anywhere.json",
    COLLECTOR_AZURE_CLIENT_ID: "synthetic-collector", REMEDIATOR_AZURE_CLIENT_ID: "synthetic-remediator",
  })).services;
  assert.equal(configured.collector.environment.AWS_WEB_IDENTITY_TOKEN_FILE, "/run/cloud-identity/aws/token");
  assert.equal(configured.collector.environment.AWS_ROLES_ANYWHERE_CONFIG, "");
  assert.equal(configured.remediator.environment.AWS_WEB_IDENTITY_TOKEN_FILE, "");
  assert.equal(configured.remediator.environment.AWS_ROLES_ANYWHERE_CONFIG, "/run/cloud-identity/aws/roles-anywhere.json");
  assert.equal(configured.collector.environment.AZURE_CLIENT_ID, "synthetic-collector");
  assert.equal(configured.remediator.environment.AZURE_CLIENT_ID, "synthetic-remediator");
});

test("only the collector runs task-runner processes, as many as configured", () => {
  assert.equal(services.collector.init, true);  // reaps a document-parser child orphaned by a killed parser server
  assert.equal(services.collector.pids_limit, 1024);  // room for 32 runners' threads and parsers
  for (const role of ["api", "remediator", "control"]) assert.equal(services[role].pids_limit, 256, role);
  assert.equal(services.collector.environment.WORKER_CONCURRENCY, "0");
  for (const role of ["remediator", "control"]) assert.equal(services[role].environment.WORKER_CONCURRENCY, undefined, role);
  assert.match(envExample, /^WORKER_CONCURRENCY=0$/m);
  assert.equal(success(render({ WORKER_CONCURRENCY: "3" })).services.collector.environment.WORKER_CONCURRENCY, "3");
});

test("ticket-system plugins reach every platform process, empty by default, never the web or SIEM", () => {
  const roles = ["api", "collector", "remediator", "control"];
  for (const role of roles) assert.equal(services[role].environment.TICKET_SYSTEM_PLUGINS, "", role);
  assert.match(envExample, /^TICKET_SYSTEM_PLUGINS=$/m);
  const configured = success(render({ TICKET_SYSTEM_PLUGINS: "jira" })).services;
  for (const role of roles) assert.equal(configured[role].environment.TICKET_SYSTEM_PLUGINS, "jira", role);
  for (const name of ["web", "siem"]) assert.equal(configured[name].environment?.TICKET_SYSTEM_PLUGINS, undefined, name);
});

const required = [...new Set([...source.matchAll(/\$\{([A-Z_0-9]+):\?/g)].map(match => match[1]))];
for (const name of required) {
  test(`missing required input ${name} fails before any service can start`, () => {
    assert.match(envExample, new RegExp(`^${name}=`, "m"), "document the input");
    const result = render({ [name]: undefined });
    assert.equal(result.error, undefined, result.error?.message);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(name));
  });
}
