import type { NextRequest } from "next/server";

/* What the link pages' proxies (app/api/owner-approval, app/api/response-link) share: a body read no further than its
 * limit, and a request that must come from the page's own origin. */

/** The body, or null when it is larger than `limit` bytes or cannot be read. */
export async function smallBody(request: NextRequest, limit: number): Promise<string | null> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
    await request.body?.cancel().catch(() => undefined);
    return null;
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
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

export function sameOrigin(request: NextRequest) {
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
