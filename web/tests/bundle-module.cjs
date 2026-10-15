/* One bundler for the browser proofs.
 *
 * A proof renders the real screen in a real browser, so it needs the module
 * graph as something a <script> can run. Every proof carried its own copy of
 * the same walk -- transpile, scan for require(), resolve, repeat -- and the
 * copies had drifted: some resolved a local import and some did not, and a
 * `.css` import returned class names in one file, an empty object in another
 * and nothing at all in a third. A component gaining a stylesheet or an import
 * therefore broke a different subset of proofs each time.
 *
 * This is that walk, once. Nothing is stubbed and nothing is bundled that the
 * modules do not ask for.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");

const { root, aliasPath } = require("../scripts/source-paths.cjs");

const COMPILER = {
  jsx: ts.JsxEmit.ReactJSX,
  module: ts.ModuleKind.CommonJS,
  target: ts.ScriptTarget.ES2022,
  esModuleInterop: true,
};

/** The file a specifier names, or null when it is a package. */
function resolve(specifier, fromDir) {
  let base;
  if (aliasPath(specifier)) base = aliasPath(specifier);
  else if (specifier.startsWith("./") || specifier.startsWith("../")) base = path.resolve(fromDir, specifier);
  else return null;
  for (const candidate of [base, base + ".tsx", base + ".ts", base + ".js"]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

/**
 * Bundle the entries and everything they import.
 *
 * `css` decides what a stylesheet import evaluates to in the page:
 *   "names"  every key is its own class name, which is what a CSS module gives
 *   "empty"  an empty map, for a proof that only needs the import not to throw
 *   "prefix" the real rules, class names prefixed so they cannot collide with
 *            the global stylesheets the proof also injects; the rewritten text
 *            is returned in `styles` for the proof to add
 *   "inject" the same, but the module adds its own <style> when it loads, for a
 *            proof that measures the page before it would get to add one
 *
 * `extraExports` maps a specifier to export statements appended to it, which is
 * how a proof reaches a screen the module does not export.
 */
function bundle(entries, { css = "inject", prefix = "bundled_", extraExports = {} } = {}) {
  const modules = {};
  const styles = [];
  const appended = Object.fromEntries(Object.entries(extraExports).map(([specifier, text]) => {
    const file = path.isAbsolute(specifier) ? specifier : resolve(specifier, root);
    if (!file) throw new Error(`no module for ${specifier}`);
    return [file, text];
  }));

  function include(specifier, fromDir = root) {
    const file = path.isAbsolute(specifier) ? specifier
      : resolve(specifier, fromDir) || require.resolve(specifier, { paths: [fromDir, root] });
    if (modules[file]) return file;
    const item = modules[file] = { code: "", dependencies: {} };

    if (file.endsWith(".css")) {
      if (css === "empty") { item.code = "module.exports={};"; return file; }
      if (css === "names") { item.code = "module.exports=new Proxy({},{get:(_,key)=>key});"; return file; }
      const names = {};
      const text = fs.readFileSync(file, "utf8").replace(/\.([A-Za-z_][\w-]*)/g,
        (_match, name) => `.${names[name] = prefix + name}`);
      item.code = `module.exports=${JSON.stringify(names)};`;
      if (css === "inject") {
        item.code += `const style=document.createElement('style');style.textContent=${JSON.stringify(text)};`
          + `document.head.appendChild(style);`;
      } else styles.push(text);
      return file;
    }
    // A JSON import is its parsed value, as the bundler gives it.
    if (file.endsWith(".json")) {
      item.code = `module.exports=${JSON.stringify(JSON.parse(fs.readFileSync(file, "utf8")))};`;
      return file;
    }

    let code = fs.readFileSync(file, "utf8") + (appended[file] || "");
    if (/\.tsx?$/.test(file)) code = ts.transpileModule(code, { compilerOptions: COMPILER }).outputText;
    for (const match of code.matchAll(/require\(["']([^"']+)["']\)/g)) {
      item.dependencies[match[1]] = include(match[1], path.dirname(file));
    }
    item.code = code;
    return file;
  }

  const names = Object.fromEntries(Object.entries(entries).map(([name, specifier]) => [name, include(specifier)]));
  // The page-side loader: the same CommonJS shim every proof was carrying.
  const preamble = `const process={env:{NODE_ENV:'production'}},modules=window.__fixture.modules,cache={};`
    + `function load(id){if(cache[id])return cache[id].exports;const m=cache[id]={exports:{}};`
    + `new Function('module','exports','require',modules[id].code)(m,m.exports,n=>load(modules[id].dependencies[n]));return m.exports}`
    + `const {${Object.keys(entries).join(",")}}=Object.fromEntries(Object.entries(window.__fixture.names).map(([k,id])=>[k,load(id)]));`;
  return { modules, names, styles, preamble, data: { modules, names } };
}

module.exports = { bundle, resolve, root };
