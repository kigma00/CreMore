/* Links back to the original source, built by the server from recorded coordinates.
 * Defence in depth: only a link whose shape matches the provider's approved pattern opens. */

import type { SourceLocation } from "@/lib/dashboard-types";

// Defence in depth only: the server constructs links from approved coordinates.
// Never use an arbitrary URL from a finding or a persisted original_link blob.
export function sourceOriginalURL(location?: SourceLocation): string | null {
  const link = location?.original_link;
  if (!link || !["AVAILABLE", "CURRENT_ONLY"].includes(link.status) || !link.requires_source_auth || !link.url) return null;
  try {
    const u = new URL(link.url);
    if (u.protocol !== "https:" || u.username || u.password) return null;
    const provider = location.source_provider.toLowerCase();
    if (["gitlab", "confluence", "bitbucket", "azure_devops"].includes(provider)) {
      const base = new URL(location.provider_instance_id || "");
      if (base.protocol !== "https:" || base.origin !== u.origin || base.username || base.password || base.search || base.hash) return null;
      const context = base.pathname.replace(/\/$/, "");
      if (!u.pathname.startsWith(`${context}/`)) return null;
      const route = u.pathname.slice(context.length);
      if (provider === "gitlab" && !u.search && /^\/(?:[\w.-]+\/)+-\/blob\/(?:[a-f\d]{40}|[a-f\d]{64})\/.+/i.test(route) && /^($|#L\d+)$/.test(u.hash)) return u.href;
      if (provider === "azure_devops" && /^\/[^/]+\/[^/]+\/_git\/[^/]+$/.test(route) && !u.hash && [...u.searchParams.keys()].sort().join() === "_a,path,version" && u.searchParams.get("_a") === "contents" && /^GC[a-f\d]{40}$/.test(u.searchParams.get("version") || "") && (u.searchParams.get("path") || "").startsWith("/")) return u.href;
      if (provider === "confluence" && route === "/pages/viewpage.action" && !u.hash && [...u.searchParams.keys()].every(k => k === "pageId") && /^\d+$/.test(u.searchParams.get("pageId") || "")) return u.href;
      if (provider === "bitbucket" && location.source_deployment === "cloud" && base.href === "https://bitbucket.org/" && !u.search && /^\/[\w.-]+\/[\w.-]+\/src\/(?:[a-f\d]{40}|[a-f\d]{64})\/.+/i.test(route) && /^($|#lines-\d+)$/.test(u.hash)) return u.href;
      if (provider === "bitbucket" && location.source_deployment === "data_center" && /^\/projects\/[\w~-]+\/repos\/[\w.-]+\/browse\/.+/.test(route) && [...u.searchParams.keys()].every(k => k === "at") && /^(?:[a-f\d]{40}|[a-f\d]{64})$/i.test(u.searchParams.get("at") || "") && /^($|#\d+)$/.test(u.hash)) return u.href;
    }
    if (u.port) return null;
    if (provider === "gcp" && u.hostname === "console.cloud.google.com" && /^\/storage\/browser\/_details\/[a-z\d][a-z\d._-]+\/.+/.test(u.pathname) && !u.hash && [...u.searchParams.keys()].every(k => k === "generation") && (!u.search || /^\d+$/.test(u.searchParams.get("generation") || ""))) return u.href;
    if (provider === "github" && githubSourceHost(location, u.hostname) && !u.search && /^\/[\w.-]+\/[\w.-]+\/blob\/(?:[a-f\d]{40}|[a-f\d]{64})\/.+/i.test(u.pathname) && /^($|#L\d+(?:-L\d+)?)$/.test(u.hash)) return u.href;
    if (provider === "notion" && u.hostname === "www.notion.so" && !u.search && /^\/[a-f\d]{32}$/i.test(u.pathname) && /^($|#[a-f\d]{32})$/i.test(u.hash)) return u.href;
    if (provider === "aws" && u.hostname === "s3.console.aws.amazon.com" && /^\/s3\/object\/[a-z\d][a-z\d.-]+$/.test(u.pathname) && !u.hash && [...u.searchParams.keys()].every((key) => ["prefix", "region", "versionId"].includes(key))) return u.href;
  } catch { /* Invalid or unapproved links stay unavailable. */ }
  return null;
}

function githubSourceHost(location: SourceLocation, host: string) {
  if (host === "github.com") return !location.provider_instance_id || location.provider_instance_id === "https://api.github.com";
  if (!["2022-11-28", "2026-03-10"].includes(location.source_api_version || "")) return false;
  const instance = location.provider_instance_id || "";
  if (location.source_deployment === "GHE_COM_DATA_RESIDENCY") return !location.source_server_version && /^api\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ghe\.com$/.test(`api.${host}`) && instance === `https://api.${host}`;
  return location.source_deployment === "GHES" && /^3\.22\.(0|[1-9][0-9]{0,3})$/.test(location.source_server_version || "") && host !== "api.github.com" && !host.endsWith(".ghe.com") && host.length <= 253 && !/^[\d.]+$/.test(host) && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(host) && instance === `https://${host}/api/v3`;
}
