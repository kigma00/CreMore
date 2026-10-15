// Public machine ingress only. The API verifies the exact body signature and
// operator-confirmed binding; no browser session or server credential is added.
export const dynamic = "force-dynamic";

const LIMIT = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const headers = { "Cache-Control": "no-store", "Content-Type": "application/json" };

export async function POST(request: Request, context: { params: Promise<{ binding: string }> }) {
  const { binding } = await context.params;
  if (!UUID.test(binding)) return new Response(null, { status: 404, headers });
  const base = process.env.CREMORE_API_URL;
  if (!base) return new Response(null, { status: 503, headers });
  const signature = request.headers.get("x-notion-signature");
  if (signature && !/^sha256=[0-9a-f]{64}$/.test(signature)) return new Response(null, { status: 403, headers });
  const reader = request.body?.getReader();
  const parts: Uint8Array[] = [];
  let length = 0;
  try {
    if (reader) while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > LIMIT) {
        await reader.cancel();
        return new Response(null, { status: 413, headers });
      }
      parts.push(value);
    }
  } catch {
    return new Response(null, { status: 400, headers });
  } finally { reader?.releaseLock(); }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { body.set(part, offset); offset += part.byteLength; }
  try {
    const response = await fetch(new URL(`/api/v1/hooks/notion/${binding}`, base), {
      method: "POST", body, cache: "no-store", redirect: "error",
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
      headers: { "Content-Type": "application/json", ...(signature ? { "X-Notion-Signature": signature } : {}) },
    });
    // ACK only after durable acceptance. Don't relay external/error bodies.
    await response.body?.cancel();
    return new Response(null, { status: response.ok ? 200 : response.status, headers });
  } catch {
    return new Response(null, { status: 502, headers });
  }
}
