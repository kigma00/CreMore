export const metadataProviders = ["github", "github_identity", "notion", "slack"] as const;
export const metadataKinds = ["credential", "principal", "installation", "policy", "request", "context", "public_key", "trust", "vault_item", "vault_version", "runner", "resource", "unknown"] as const;
export type MetadataFact = { name: string; state: string; value?: string | number | boolean | (string | number | boolean)[] | null; container?: string | null; children: MetadataFact[]; reason?: string | null };
export type MetadataPage<T> = { items: T[]; total: number; offset: number; limit: number; next_offset?: number | null };
const object = (v: unknown): Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : {};
const count = (v: unknown) => Number.isSafeInteger(v) && Number(v) >= 0;
function checkFacets(value: unknown, keys: string[]) {
  if (value !== undefined && keys.some(key => !Array.isArray(object(value)[key])
    || !(object(value)[key] as unknown[]).every(item => typeof item === "string"))) throw Error("METADATA_FACETS_INVALID");
}

export function metadataPage<T>(v: unknown): MetadataPage<T> {
  const p = object(v);
  if (!Array.isArray(p.items) || p.items.length > 500 || ![p.total, p.offset, p.limit].every(count) || Number(p.limit) < 1 || Number(p.limit) > 500 || p.items.length > Number(p.limit) || p.items.length > Number(p.total)) throw Error("METADATA_PAGE_INVALID");
  return p as unknown as MetadataPage<T>;
}
export type MetadataEventSubject = { entity_id: string; object_id: string; object_kind: string };
export type MetadataEvent = {
  id: string; provider: string; connection_id: string; run_id: string;
  event_type: string; event_id: string; occurred_at: string | null; observed_at: string;
  match_basis: string; confidence: string;
  subject: MetadataEventSubject | null; target: MetadataEventSubject | null; facts: MetadataFact[];
};
export type MetadataEvents = MetadataPage<MetadataEvent> & {
  schema_version: 2; event_types: string[]; boundary: "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS";
  facets?: Record<"provider" | "event_type", string[]>;
  facets_truncated?: boolean; event_types_truncated?: boolean;
};

export function metadataEvents(v: unknown): MetadataEvents {
  const page = metadataPage<MetadataEvent>(v), body = object(v);
  // The boundary is part of the payload. A response that does not declare
  // itself provider-reported is refused rather than rendered beside the
  // local audit log, where it would read as something a person did here.
  if (body.schema_version !== 2 || body.boundary !== "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS"
    || !Array.isArray(body.event_types) || !body.event_types.every(v => typeof v === "string")) throw Error("METADATA_EVENTS_INVALID");
  checkFacets(body.facets, ["provider", "event_type"]);
  if ([body.facets_truncated, body.event_types_truncated].some(value => value !== undefined && typeof value !== "boolean")) throw Error("METADATA_FACETS_INVALID");
  for (const item of page.items) {
    const e = object(item);
    if (typeof e.id !== "string" || typeof e.event_type !== "string" || typeof e.event_id !== "string"
      || !metadataProviders.includes(e.provider as typeof metadataProviders[number])
      || !["PROVIDER_ID", "PROVIDER_EXPLICIT", "AUDIT_REFERENCE", "IDENTIFIER", "CANDIDATE", "POLICY", "UNKNOWN"].includes(String(e.match_basis))
      || !["EXACT", "IDENTIFIER", "CANDIDATE", "UNKNOWN"].includes(String(e.confidence))) throw Error("METADATA_EVENTS_INVALID");
    for (const side of ["subject", "target"] as const) {
      if (e[side] === null) continue;
      const s = object(e[side]);
      if (typeof s.entity_id !== "string" || typeof s.object_id !== "string"
        || !metadataKinds.includes(s.object_kind as typeof metadataKinds[number])) throw Error("METADATA_EVENTS_INVALID");
    }
  }
  return v as MetadataEvents;
}
