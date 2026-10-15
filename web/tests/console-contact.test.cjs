// Owner contact that CreMore sends itself: what the integrations card says, the lists an admin types, and the
// setup a save sends (an empty password or token keeps the saved one).
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");

const delivery = load("@/console/views/integrations/contact-delivery.tsx");
const plain = value => JSON.parse(JSON.stringify(value));
const L = (ko, en) => en;

test("the card names the channels CreMore sends on", () => {
  assert.equal(delivery.contactState(undefined, L), "Not set up");
  assert.equal(delivery.contactState({ mail: true, slack: false, allowed_domains: [] }, L), "Mail");
  assert.equal(delivery.contactState({ mail: true, slack: true, allowed_domains: ["example.com"] }, L), "Mail · Slack");
});

test("a typed list splits on commas, semicolons, spaces and lines, once each", () => {
  assert.deepEqual(plain(delivery.listOf("kim@example.com, lee@example.com;\n#security-alerts  kim@example.com")),
    ["kim@example.com", "lee@example.com", "#security-alerts"]);
  assert.deepEqual(plain(delivery.listOf("  ")), []);
});

test("a save sends each channel that is on, lower-cased domains, and an empty secret as it is", () => {
  const form = { mail: true, host: " smtp.example.com ", port: "587", security: "starttls", username: "cremore", password: "",
    from_address: "security@example.com ", from_name: " 보안팀 ", slack: false, token: "", channels: "#security-alerts,\nC0123ABCD9",
    domains: "Example.com, corp.example.com", console: " https://cremore.example.com " };
  assert.deepEqual(plain(delivery.contactBody(form)), {
    mail: { host: "smtp.example.com", port: 587, security: "starttls", username: "cremore", password: "", from_address: "security@example.com", from_name: "보안팀" },
    slack: null, allowed_domains: ["example.com", "corp.example.com"], console_url: "https://cremore.example.com" });
  const token = "xoxb" + "-token";  // built at run time: nothing token-shaped sits in the source
  assert.deepEqual(plain(delivery.contactBody({ ...form, mail: false, slack: true, token: ` ${token} ` })).slack,
    { token, allowed_channels: ["#security-alerts", "C0123ABCD9"] });
  assert.equal(plain(delivery.contactBody({ ...form, mail: false })).mail, null);
});
