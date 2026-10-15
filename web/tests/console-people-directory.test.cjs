// A team install reads people only from the IdP people sign in with: the wizard and the directory menu say why the
// others are closed, and open the sign-in IdP filled in. Synthetic catalogs only; the API decides.
const test = require("node:test");
const assert = require("node:assert/strict");
const { load, source } = require("./load-module.cjs");

const model = load("@/console/views/integrations/model.ts");
const ko = (text, _en) => text;

const descriptor = (provider, extra = {}) => ({ provider, label: provider, label_ko: provider, category: "identity",
  editions: [{ id: "cloud", label: "c", label_ko: "c" }], purposes: { identity: {} }, auth_methods: [], ...extra });
const okta = descriptor("okta", { label: "Okta", label_ko: "Okta",
  target: [{ name: "organization", label: "Okta organization host", label_ko: "Okta 조직 호스트" }] });
const providers = [okta, descriptor("keycloak"), descriptor("github", { category: "code" }),
  descriptor("azure", { category: "cloud", purposes: { inventory: {}, identity: {} } }),
  descriptor("entra_id", { replaced_by: "azure" })];
const catalog = sign_in_idp => ({ purposes: [], providers, sign_in_idp });
const exempt = ["github"];  // as the API names them (cremore.onboarding.sign_in.EXEMPT)
const oktaSignIn = { issuer: "https://acme.okta.com/oauth2/default", provider: "okta", target: { organization: "acme.okta.com" }, exempt };

test("a single operator's install takes any people directory", () => {
  for (const d of providers) assert.equal(model.peopleDirectoryBlock(catalog(null), d, {}, ko), null, d.provider);
});

test("on a team install only the sign-in IdP, at its own organization, reads people; GitHub's link stays open", () => {
  const team = catalog(oktaSignIn);
  assert.equal(model.peopleDirectoryBlock(team, okta, null, ko), null);
  assert.equal(model.peopleDirectoryBlock(team, okta, { organization: "https://ACME.okta.com/" }, ko), null);
  assert.equal(model.peopleDirectoryBlock(team, okta, { organization: "acme.okta.com:443" }, ko), null);
  assert.match(model.peopleDirectoryBlock(team, okta, { organization: "other.okta.com" }, ko), /Okta 조직 호스트 acme\.okta\.com/);
  assert.match(model.peopleDirectoryBlock(team, providers[1], null, ko), /로그인에 쓰는 IdP\(Okta\)로만/);
  assert.equal(model.peopleDirectoryBlock(team, providers[2], null, ko), null);
  const entra = catalog({ issuer: "https://login.microsoftonline.com/t/v2.0", provider: "azure", target: { tenant: "t" }, exempt });
  assert.equal(model.peopleDirectoryBlock(entra, providers[4], { tenant: "t" }, ko), null);  // the provider it replaced
  assert.match(model.peopleDirectoryBlock(catalog({ issuer: "https://idp.test", provider: null, target: null, exempt }), okta, null, ko),
    /https:\/\/idp\.test/);
  for (const code of ["PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP", "PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN"]) {
    assert.match(model.onboardingText(code, [], ko), /팀 설치/);
  }
});

test("the directory menu opens the sign-in IdP filled in and closes the others with the reason", () => {
  const page = source("@/console/views/integrations/page.tsx");
  assert.match(page, /openChooser\(element, L\("디렉터리 연동", "Connect a directory"\), idpProviders, true\)/);
  assert.match(page, /disabled=\{Boolean\(block\)\} tip=\{block \?\? undefined\}/);
  assert.match(page, /if \(signIn\) setWizard\(\{ provider, purpose: "identity", target: signIn\.target \?\? \{\} \}\)/);
  assert.match(page, /else openConnect\(provider, chooser\.entry\)/);
  const wizard = source("@/console/views/integrations/wizard.tsx");
  // Filled in only when it opens to read people: a Microsoft connection for another tenant's inventory starts empty.
  assert.match(wizard, /catalog\.sign_in_idp\?\.provider === d\.provider\s*&& \(\("provider" in open && open\.purpose === "identity"\) \|\| purposesOf\(d\)\.every\(p => p === "identity"\)\)/);
});
