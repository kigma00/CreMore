/* The scan scope as the console reads and sends it: the catalog a connection lists (checked as it arrives, so a
 * malformed or mismatched answer is refused rather than shown) and an empty scope profile to start from. Plain data and
 * functions, so pure models and tests can import it. Moved from the dashboard's scan scope panel, unchanged. */

export type ScopeConnection = { kind: "aws" | "source"; connection_id: string; display_name?: string; provider?: string };
export type ScopeResource = { id: string; provider_resource_id: string; resource_type: string; display_name: string; canonical_reference: string; provider_instance_id: string; account_id?: string; region?: string; organization_id?: string; workspace_id?: string; parent_id?: string; known_root_ids?: string[]; visibility: string; archived?: boolean; fork?: boolean; language?: string; topics?: string[] | null; default_branch?: string; last_edited_at?: string; last_sync_status?: string; last_synced_at?: string; last_scan_status?: string; last_scan_at?: string; scan_status_basis?: string; subtree_expansion_allowed?: boolean; list_visibility: string; content_readiness: string; reason_code?: string };
export type ScopeCatalog = ScopeConnection & { catalog_snapshot_id: string; auth_revision: string; items: ScopeResource[]; catalog_completeness: string; reason_code?: string; last_refreshed_at: string; known_count: number; count_accuracy: string; has_more: boolean; next_cursor?: string; available_filters: string[]; metadata_search_enabled?: boolean };
export type ScopeSelection = { resource_id: string; all_current_objects: boolean; prefixes: string[]; excluded_prefixes: string[]; ref?: string; paths: string[]; excluded_paths: string[]; page_mode?: string; descendant_ids: string[]; include_future_descendants: boolean };
export type ScopeBudgets = { bytes: number; requests: number; seconds: number };
export type ScopeProfileInput = { expected_version: number; name: string; selected_roots: ScopeSelection[]; excluded_ids: string[]; budgets: ScopeBudgets; schedule_minutes: number; full_scan_minutes?: number | null; event_mode: string; change_reason: string; catalog_snapshot_id: string };
const object = (value: unknown): Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const string = (value: unknown) => typeof value === "string" && value.length <= 4096;
const integer = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 0;
const strings = (value: unknown, max = 20000): value is string[] => Array.isArray(value) && value.length <= max && value.every(item => string(item) && item.length > 0);
const list = (value: unknown): unknown[] => value === null ? [] : Array.isArray(value) ? value : (() => { throw Error("SCOPE_RESPONSE_INVALID"); })();
function identity(value: unknown, connection: ScopeConnection) {
  const data = object(value);
  if (data.kind !== connection.kind || data.connection_id !== connection.connection_id) throw Error("SCOPE_RESPONSE_MISMATCH");
  return data;
}
function resource(value: unknown): ScopeResource {
  const data = object(value);
  if (![data.id, data.provider_resource_id, data.resource_type, data.display_name, data.canonical_reference, data.provider_instance_id, data.list_visibility, data.content_readiness].every(string) || !data.id || !data.provider_resource_id) throw Error("SCOPE_RESPONSE_INVALID");
  if (["language", "last_sync_status", "last_scan_status", "scan_status_basis"].some(key => data[key] !== undefined && !string(data[key])) || ["last_edited_at", "last_synced_at", "last_scan_at"].some(key => data[key] !== undefined && !Number.isFinite(Date.parse(String(data[key])))) || data.topics != null && !strings(data.topics, 1000) || data.known_root_ids !== undefined && !strings(data.known_root_ids, 10000) || data.subtree_expansion_allowed !== undefined && typeof data.subtree_expansion_allowed !== "boolean") throw Error("SCOPE_RESPONSE_INVALID");
  return data as unknown as ScopeResource;
}
export function projectScopeCatalog(value: unknown, connection: ScopeConnection): ScopeCatalog {
  const data = identity(value, connection), items = list(data.items).map(resource), filters = list(data.available_filters);
  if (items.length > 200 || new Set(items.map(item => item.id)).size !== items.length || ![data.catalog_snapshot_id, data.auth_revision, data.catalog_completeness, data.count_accuracy, data.last_refreshed_at].every(string) || !integer(data.known_count) || typeof data.has_more !== "boolean" || (data.has_more && (!string(data.next_cursor) || !data.next_cursor)) || !filters.every(string)) throw Error("SCOPE_RESPONSE_INVALID");
  if (data.metadata_search_enabled !== undefined && typeof data.metadata_search_enabled !== "boolean") throw Error("SCOPE_RESPONSE_INVALID");
  return { ...data, items, available_filters: filters } as unknown as ScopeCatalog;
}
export const defaultScopeInput = (): ScopeProfileInput => ({ expected_version: 0, name: "", selected_roots: [], excluded_ids: [], budgets: { bytes: 536870912000, requests: 2000000, seconds: 21600 }, schedule_minutes: 0, event_mode: "DISABLED", change_reason: "", catalog_snapshot_id: "" });
