/* What a failed `/api/backend` call raises.
 *
 * The status travels with the message because the dashboard reacts to it: 401
 * and 403 end the session, 409 means somebody else is already doing this. It is
 * its own module so the code that raises it and the code that turns it into a
 * sentence can both have it without importing each other.
 */

/* Every call the dashboard makes goes through here: to the Next.js proxy, which
 * attaches the credential, never to the API directly. A non-2xx becomes a
 * DashboardAPIError carrying the status, because the dashboard reacts to it. */
async function readOnce<T>(path: string, init?: RequestInit): Promise<{ data: T; headers: Headers; status: number }> {
  const response = await fetch(`/api/backend/${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  const data = await response
    .json()
    .catch(() => ({ error: "Invalid server response" }));
  if (!response.ok) throw new DashboardAPIError(data.error ?? "Request failed", response.status);
  return { data: data as T, headers: response.headers, status: response.status };
}

/** Isolated AWS reads run in the collector; follow only the exact local request endpoint. */
async function read<T>(path: string, init?: RequestInit): Promise<{ data: T; headers: Headers }> {
  let result = await readOnce<T>(path, init);
  const queued = result.data as { request_id?: string; poll_url?: string } | null;
  if (result.status !== 202 || !queued?.request_id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(queued.request_id)
    || queued.poll_url !== `/api/v1/aws/requests/${queued.request_id}`) return result;
  const poll = `aws/requests/${queued.request_id}`;
  for (let attempt = 0; attempt < 120; attempt++) {
    init?.signal?.throwIfAborted();
    await new Promise<void>((resolve, reject) => {
      const done = () => { init?.signal?.removeEventListener("abort", abort); resolve(); };
      const timer = setTimeout(done, 1000);
      const abort = () => { clearTimeout(timer); init?.signal?.removeEventListener("abort", abort); reject(init?.signal?.reason); };
      init?.signal?.addEventListener("abort", abort, { once: true });
    });
    result = await readOnce<T>(poll, { signal: init?.signal });
    if (result.status !== 202) return result;
  }
  throw new DashboardAPIError("AWS_READ_PENDING: collection is still running; check the worker before requesting again", 409);
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  return (await read<T>(path, init)).data;
}

export type APIPage<T> = { data: T; nextCursor: string | null; pageLimit: number | null };

/** Array APIs retain their response shape and carry pagination in response headers. */
export async function apiPage<T>(path: string): Promise<APIPage<T>> {
  const { data, headers } = await read<T>(path);
  const cursor = headers.get("X-Next-Cursor"), limit = Number(headers.get("X-Page-Limit"));
  return { data, nextCursor: cursor || null, pageLimit: Number.isInteger(limit) && limit > 0 ? limit : null };
}

export class DashboardAPIError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}
