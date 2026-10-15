import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ path: string[] }> };

function bodyLimit(method: string, path: string[]) {
  const scopeWrite = (method === "PATCH" && path.length === 2 && path[0] === "scan-scope-profiles") ||
    (method === "POST" && path.length === 4 && path[0] === "connections" && ["scan-scope-profiles", "selection-drafts"].includes(path[3])) ||
    (method === "POST" && path.length === 5 && path[0] === "connections" && ["aws", "source"].includes(path[1]) && path[3] === "resources" && path[4] === "search");
  return (scopeWrite ? 8 : 1) * 1024 * 1024;
}

async function boundedBody(request: NextRequest, limit: number): Promise<string | Response> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength)))) {
    return NextResponse.json({ error: "invalid content length" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  if (contentLength !== null && Number(contentLength) > limit) {
    await request.body?.cancel().catch(() => undefined);
    return NextResponse.json({ error: "request body is too large" }, { status: 413, headers: { "Cache-Control": "no-store" } });
  }
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel().catch(() => undefined);
        return NextResponse.json({ error: "request body is too large" }, { status: 413, headers: { "Cache-Control": "no-store" } });
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return new TextDecoder().decode(bytes);
  } catch {
    return NextResponse.json({ error: "request body could not be read" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  } finally {
    reader.releaseLock();
  }
}

async function proxy(request: NextRequest, context: Context) {
  const base = process.env.CREMORE_API_URL;
  const mode = process.env.CREMORE_AUTH_MODE ?? "local";
  if (!base) {
    return NextResponse.json({ error: "server API connection is not configured" }, { status: 503 });
  }
  let authorization: string | null = null;
  if (mode === "local") {
    // This proxy attaches an admin credential, so a page whose DNS was rebound
    // to 127.0.0.1 must not reach it: only the browser-set Host (never
    // X-Forwarded-Host, which same-origin script can add) is trusted here.
    if (!allowedLocalHost(request.headers.get("host"), process.env.CREMORE_ALLOWED_HOSTS)) {
      return NextResponse.json({ error: "host is not allowed for local authentication" }, { status: 403, headers: { "Cache-Control": "no-store" } });
    }
    const token = process.env.CREMORE_API_TOKEN;
    if (!token) {
      return NextResponse.json({ error: "local API token is not configured" }, { status: 503 });
    }
    authorization = `Bearer ${token}`;
  } else if (mode === "oidc") {
    authorization = request.headers.get("authorization");
    if (!authorization?.match(/^Bearer [^\s]+$/i) || authorization.length > 16 * 1024) {
      return NextResponse.json({ error: "authenticated OIDC session is required" }, { status: 401 });
    }
  } else {
    return NextResponse.json({ error: "server authentication mode is invalid" }, { status: 503 });
  }
  // The local token is a server credential too; it must not turn a cross-site
  // browser request into an authenticated mutation.
  if (!["GET", "HEAD"].includes(request.method) && !sameOrigin(request)) {
    return NextResponse.json({ error: "cross-origin mutation is forbidden" }, { status: 403, headers: { "Cache-Control": "no-store" } });
  }
  const { path } = await context.params;
  // Only declared namespaces upgrade the API version. Google OAuth still uses
  // the same dashboard session and same-origin mutation checks above.
  const gcpOAuth = path.length === 4 && path[1] === "gcp" && path[2] === "oauth"
    && ["status", "client", "start", "finish", "projects", "complete", "cancel"].includes(path[3]);
  if (path.some(segment => !segment || segment === "." || segment === "..") ||
      (path[0] === "v2" && path[1] !== "coverage" && !gcpOAuth)) {
    return NextResponse.json({ error: "unsupported API path" }, { status: 404, headers: { "Cache-Control": "no-store" } });
  }
  const version = path[0] === "v2" ? "v2" : "v1";
  const safePath = (version === "v2" ? path.slice(1) : path).map(encodeURIComponent).join("/");
  const upstream = new URL(`/api/${version}/${safePath}`, base);
  upstream.search = request.nextUrl.search;
  const headers = new Headers({ Authorization: authorization, Accept: "application/json" });
  const init: RequestInit = { method: request.method, headers, cache: "no-store", redirect: "error", signal: request.signal };
  if (!["GET", "HEAD"].includes(request.method)) {
    headers.set("Content-Type", "application/json");
    const body = await boundedBody(request, bodyLimit(request.method, path));
    if (typeof body !== "string") return body;
    init.body = body;
  }
  try {
    const response = await fetch(upstream, init);
    // A 204 or 304 carries no body, and a Response built with one (even empty) throws.
    const body = [101, 204, 205, 304].includes(response.status) ? null : response.body;
    const replyHeaders = new Headers({ "Content-Type": response.headers.get("Content-Type") ?? "application/json", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" });
    for (const name of ["X-Next-Cursor", "X-Page-Limit"]) {
      const value = response.headers.get(name);
      if (value !== null) replyHeaders.set(name, value);
    }
    return new NextResponse(body, {
      status: response.status,
      headers: replyHeaders,
    });
  } catch {
    return NextResponse.json({ error: "API is unavailable" }, { status: 502 });
  }
}

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

// Host header hostname (port ignored) must be loopback or listed in
// CREMORE_ALLOWED_HOSTS (comma-separated hostnames, e.g. "cremore.internal").
function allowedLocalHost(host: string | null, extra = "") {
  if (!host) return false;
  const match = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{1,5})?$/i.exec(host.trim());
  if (!match) return false;
  const allowed = [...LOOPBACK_HOSTS, ...extra.split(",").map((name) => name.trim().toLowerCase()).filter(Boolean)];
  return allowed.includes(match[1].toLowerCase());
}

function sameOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim();
  const host = forwardedHost || request.headers.get("host");
  const forwardedProtocol = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim();
  const protocol = forwardedProtocol || request.nextUrl.protocol.replace(":", "");
  if (!origin || !host || !["http", "https"].includes(protocol)) return false;
  try {
    return new URL(origin).origin.toLowerCase() === `${protocol}://${host}`.toLowerCase();
  } catch {
    return false;
  }
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const PUT = proxy;
export const DELETE = proxy;
