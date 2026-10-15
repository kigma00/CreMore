"use strict";
const path = require("node:path");
const { compilerOptions: { paths } } = require("../tsconfig.json");

const root = path.join(__dirname, "..");
// The TypeScript aliases are also the source of truth for synthetic proofs.
const aliases = Object.entries(paths);
function aliasPath(specifier) {
  for (const [pattern, [target]] of aliases) {
    const prefix = pattern.slice(0, -1);
    if (specifier.startsWith(prefix)) return path.resolve(root, target.replaceAll("*", specifier.slice(prefix.length)));
  }
  return null;
}

module.exports = { root, aliasPath };
