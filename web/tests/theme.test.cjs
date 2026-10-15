const test = require("node:test");
const { source: readSource } = require("./load-module.cjs");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const { load } = require("./load-theme.cjs");

test("the root layout applies a saved theme before paint without hydration warnings", () => {
  const layout = readSource("@/app/(console)/layout.tsx");
  assert.match(layout, /suppressHydrationWarning/);
  assert.match(layout, /dangerouslySetInnerHTML=\{\{ __html: themeInitScript \}\}/);
  const { themeInitScript, themeStorageKey } = load();
  assert.ok(themeInitScript.includes(`localStorage.getItem(${JSON.stringify(themeStorageKey)})`), "inline script reads the shared storage key");
  for (const [stored, expected] of [["dark", "dark"], ["light", "light"], ["bogus", null], [null, null]]) {
    const attributes = {};
    const context = { localStorage: { getItem: key => (key === themeStorageKey ? stored : null) }, document: { documentElement: { setAttribute: (k, v) => { attributes[k] = v; } } } };
    vm.runInNewContext(themeInitScript, context);
    assert.equal(attributes["data-theme"] ?? null, expected, `stored ${stored}`);
  }
  vm.runInNewContext(themeInitScript, { get localStorage() { throw new Error("blocked"); }, document: {} });
});

test("theme preference writes the attribute and device storage; system clears both", () => {
  const attributes = {}, storage = new Map(), listeners = {};
  const window = { localStorage: { getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) }, addEventListener: (n, f) => { listeners[n] = f; }, removeEventListener: () => {} };
  const document = { documentElement: { setAttribute: (k, v) => { attributes[k] = v; }, removeAttribute: k => { delete attributes[k]; } } };
  const theme = load({ window, document });
  theme.setThemePreference("dark");
  assert.equal(attributes["data-theme"], "dark");
  assert.equal(storage.get(theme.themeStorageKey ?? "cremore.theme.v1"), "dark");
  theme.setThemePreference("nonsense");
  assert.equal(attributes["data-theme"], "dark", "unknown values are ignored");
  theme.setThemePreference("system");
  assert.equal(attributes["data-theme"], undefined);
  assert.equal(storage.size, 0);
});
