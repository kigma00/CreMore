/* One loader for every dashboard module a test needs.
 *
 * A test used to name each dependency of the module it wanted and hand back a
 * copy it had loaded itself, which meant a thirty-name ternary in one file and
 * a new line in several files whenever a component gained an import. Nothing
 * about that was checked: a stale name silently fell through to Node's own
 * require and failed somewhere else.
 *
 * This resolves a specifier the way the bundler does instead -- "@/lib/x" and
 * "./x" both become a file, transpiled once and cached, and the imports inside
 * it resolve through the same path. Nothing is stubbed; a test that wants a
 * stub passes it explicitly.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("typescript");
const React = require("react");

const { root, aliasPath } = require("../scripts/source-paths.cjs");
const cache = new Map();

const COMPILER = {
  jsx: ts.JsxEmit.ReactJSX,
  module: ts.ModuleKind.CommonJS,
  target: ts.ScriptTarget.ES2022,
  esModuleInterop: true,
};

// What the browser gives a `.module.css` import is a map of names; every key
// here is its own class name, which is what the class-name assertions read.
const styleNames = () => new Proxy({}, { get: (_target, key) => (typeof key === "string" ? key : undefined) });

/** The file a specifier names, or null when it is a package. */
function resolve(specifier, fromDir) {
  let base;
  if (aliasPath(specifier)) base = aliasPath(specifier);
  else if (specifier.startsWith("./") || specifier.startsWith("../")) base = path.resolve(fromDir, specifier);
  else return null;
  for (const candidate of [base, base + ".tsx", base + ".ts", path.join(base, "index.tsx"), path.join(base, "index.ts")]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

/**
 * Load one module.
 *
 * `extraExports` appends export statements, which is how a test reaches an
 * internal a component does not export. `overrides` replaces a specifier for
 * THIS module only, not for what it imports, so a scripted `react` reaches the
 * component under test and not everything beneath it. Either one makes the
 * result particular to one test, so it is not cached.
 */
function load(specifier, { from = root, extraExports = "", overrides = {}, globals = {} } = {}) {
  const filename = path.isAbsolute(specifier) ? specifier : resolve(specifier, from);
  if (!filename) throw new Error(`no dashboard module for ${specifier} (from ${from})`);
  // A JSON import is its parsed value, as the bundler gives it.
  if (filename.endsWith(".json")) return JSON.parse(fs.readFileSync(filename, "utf8"));
  const particular = extraExports || Object.keys(overrides).length || Object.keys(globals).length;
  if (!particular && cache.has(filename)) return cache.get(filename);

  const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8") + extraExports, { compilerOptions: COMPILER }).outputText;
  const module = { exports: {} };
  const dir = path.dirname(filename);
  const context = {
    module, exports: module.exports, React,
    require: (name) => {
      if (name in overrides) return overrides[name];
      if (name.endsWith(".css")) return styleNames();
      const target = resolve(name, dir);
      return target ? load(target) : require(name);
    },
    console, URL, URLSearchParams, FormData, TextEncoder, TextDecoder, AbortController,
    // Web globals a client component may legitimately use; without them the
    // module still loads and the behaviour silently changes instead.
    btoa, atob, structuredClone, crypto,
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    Error, Promise, Intl, Date, Math, JSON, process,
    ...globals,
  };
  vm.runInNewContext(compiled, context, { filename });
  if (!particular) cache.set(filename, module.exports);
  return module.exports;
}

/** The source text of a module, for the tests that read it rather than run it. */
function source(specifier, from = root) {
  const filename = path.isAbsolute(specifier) ? specifier : resolve(specifier, from);
  if (!filename) throw new Error(`no dashboard module for ${specifier}`);
  return fs.readFileSync(filename, "utf8");
}

module.exports = { load, source, resolve, styleNames, root };
