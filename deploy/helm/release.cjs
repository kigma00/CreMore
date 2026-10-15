// Package only the images produced by this workflow run. No registry lookups.
const { cpSync, mkdirSync, readFileSync, writeFileSync } = require("node:fs");
const path = require("node:path");

const components = ["api", "worker", "web", "oauth2-proxy"];
function once(text, pattern, replacement) {
  let count = 0;
  const result = text.replace(pattern, (...args) => {
    count++;
    return typeof replacement === "function" ? replacement(...args) : replacement;
  });
  if (count !== 1) throw new Error(`Expected one chart image setting: ${pattern}`);
  return result;
}
function prepareRelease(repository, sha, artifacts, chart, destination) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !/^[a-f0-9]{40}$/.test(sha)) {
    throw new Error("Invalid release repository or source SHA");
  }
  const images = {};
  for (const component of components) {
    const record = JSON.parse(readFileSync(path.join(artifacts, `release-image-${component}`, `${component}.json`), "utf8"));
    const expected = `ghcr.io/${repository.toLowerCase()}-${component}`;
    if (record.component !== component || record.image !== expected || record.sha !== sha ||
        typeof record.digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(record.digest)) {
      throw new Error(`Invalid signed image reference for ${component}`);
    }
    images[component] = `${expected}@${record.digest}`;
  }
  // These four scalar locations are deliberately checked exactly once. A chart
  // layout change must update this packager instead of publishing stale tags.
  let values = readFileSync(path.join(chart, "values.yaml"), "utf8");
  values = once(values, /^image:\r?\n(?:[ ]+[^\r\n]*\r?\n)*/gm, block => {
    block = once(block, /^  requireDigest: false\r?$/gm, "  requireDigest: true");
    for (const component of components.slice(0, 3)) {
      block = once(block, new RegExp(`^  ${component}: [^\\r\\n]+\\r?$`, "gm"), `  ${component}: ${images[component]}`);
    }
    return block;
  });
  values = once(values, /(^    oauth2Proxy:\r?\n)      image: [^\r\n]+\r?$/gm,
    (_match, prefix) => `${prefix}      image: ${images["oauth2-proxy"]}`);
  const stagedChart = path.join(destination, "chart");
  mkdirSync(destination, { recursive: true });
  cpSync(chart, stagedChart, { recursive: true, errorOnExist: true, force: false });
  writeFileSync(path.join(stagedChart, "values.yaml"), values);
  const service = (name, image) =>
    `  ${name}:\n    image: ${image}\n    build: !reset null\n    pull_policy: always\n`;
  const header = "# Generated from this release's signed images. Apply after all other overlays.\nservices:\n";
  writeFileSync(path.join(destination, "compose.release.yml"), header +
    components.map(name => service(name, images[name])).join("") +
    service("caddy", "caddy@sha256:${CREMORE_CADDY_SHA256:?set a verified upstream Caddy sha256 digest (64 hex characters)}"));
  // Separate files avoid enabling optional services when only the core is used.
  for (const [file, name] of [["siem", "siem"], ["identity", "identity-refresher"]]) {
    writeFileSync(path.join(destination, `compose.release.${file}.yml`), header + service(name, images.worker));
  }
  writeFileSync(path.join(destination, "release-images.json"), JSON.stringify({ repository, sha, images }, null, 2) + "\n");
  return { images, stagedChart };
}
module.exports = { prepareRelease };
if (require.main === module) {
  if (process.argv.length !== 7) throw new Error("Usage: node release.cjs REPOSITORY SHA ARTIFACTS CHART DESTINATION");
  prepareRelease(...process.argv.slice(2));
}
