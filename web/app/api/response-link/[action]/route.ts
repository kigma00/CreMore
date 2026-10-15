import { NextRequest, NextResponse } from "next/server";

import { sameOrigin, smallBody } from "@/lib/link-proxy";

export const dynamic = "force-dynamic";

// The response link page's only way to the API: three endpoints that take the link's token in the body and the
// person's own company sign-in, which oauth2-proxy hands this route as a bearer and which goes on as it came.
// Never the local admin token (that proxy is ../../backend/[...path]). Mirrors ../../owner-approval/[action].
const ACTIONS = ["view", "answer", "evidence-options"];
// A 2,000-character Korean explanation is about 6 KB of UTF-8; the rest of a report is small.
const LIMIT = 16 * 1024;
const HEADERS = { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" };

type Context = { params: Promise<{ action: string }> };

function refuse(error: string, status: number) {
  return NextResponse.json({ error }, { status, headers: HEADERS });
}

export async function POST(request: NextRequest, context: Context) {
  const base = process.env.CREMORE_API_URL;
  if (!base) return refuse("server API connection is not configured", 503);
  if (!sameOrigin(request)) return refuse("cross-origin request is forbidden", 403);
  const { action } = await context.params;
  if (!ACTIONS.includes(action)) return refuse("unsupported API path", 404);
  const body = await smallBody(request, LIMIT);
  if (body === null) return refuse("request body is too large", 413);
  const headers = new Headers({ "Content-Type": "application/json", Accept: "application/json" });
  const authorization = request.headers.get("authorization");
  if (authorization && authorization.length <= 16 * 1024 && /^Bearer [^\s]+$/i.test(authorization)) headers.set("Authorization", authorization);
  try {
    const response = await fetch(new URL(`/api/v1/response-links/${action}`, base), {
      method: "POST", headers, body, cache: "no-store", redirect: "error", signal: request.signal,
    });
    return new NextResponse(await response.text(), {
      status: response.status, headers: { "Content-Type": response.headers.get("Content-Type") ?? "application/json", ...HEADERS },
    });
  } catch {
    return refuse("API is unavailable", 502);
  }
}
