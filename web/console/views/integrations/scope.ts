/* The exposure scope an integration's wizard sets: everything the connection's catalog lists, or the
 * resources whose names match the patterns an admin typed. The catalog is listed first (a metadata
 * refresh the worker runs; listing approves nothing), the matches are frozen into exact resource ids
 * and saved as the approved scope profile, which is previewed and started as the first run. */

import { send } from "@/console/data";
import type { Say } from "@/console/text";
import type { ProviderConnection } from "@/console/views/integrations/model";
import { defaultScopeInput } from "@/lib/scan-scope";
import { api, DashboardAPIError } from "@/lib/dashboard-api";

export type ScopeTarget = { kind: "source" | "aws"; id: string; sourceType: string; name: string };
export type ScopeMode = "all" | "named";

/** Where a connection's exposure scan reads: its content sources, or for AWS its accounts' buckets. */
export function scopeTargets(c: ProviderConnection): ScopeTarget[] {
  if (!c.plans.exposure) return [];
  const content = c.children.filter(child => child.kind === "content" && child.purpose === "exposure")
    .map(child => ({ kind: "source" as const, id: child.id, sourceType: child.source_type ?? c.provider, name: child.name ?? "" }));
  const accounts = c.provider === "aws" ? c.children.filter(child => child.kind === "aws_account")
    .map(child => ({ kind: "aws" as const, id: child.id, sourceType: "s3", name: child.account_id ?? child.name ?? "" })) : [];
  return [...content, ...accounts];
}

const base = (target: ScopeTarget) => `connections/${target.kind}/${encodeURIComponent(target.id)}`;

type CatalogView = { catalog_snapshot_id: string; catalog_completeness: string; known_count: number; reason_code?: string };
type Draft = { resource_ids: string[]; catalog_snapshot_id: string; unknown_remainder: boolean };
export type SavedProfile = { id: string; version: number; name: string; state: string; selected_roots: { resource_id: string }[]; excluded_ids: string[]; approved_at: string;
  event_mode?: string };
type Profiles = { profiles: SavedProfile[]; state: string };

/** The resources a saved scope reads (roots not excluded), across a target's profiles. */
export function scopedCount(profiles: SavedProfile[]): number {
  const ids = new Set<string>();
  for (const profile of profiles) {
    const excluded = new Set(profile.excluded_ids);
    for (const root of profile.selected_roots) if (!excluded.has(root.resource_id)) ids.add(root.resource_id);
  }
  return ids.size;
}

export function readProfiles(target: ScopeTarget): Promise<Profiles> {
  return api<Profiles>(`${base(target)}/scan-scope-profiles`);
}

/** What a resource is called where a target reads: repositories, buckets, pages. */
export function unitOf(sourceType: string, L: Say): string {
  if (sourceType === "s3" || sourceType === "gcp") return L("버킷", "buckets");
  if (sourceType === "azure_blob") return L("컨테이너", "containers");
  if (sourceType === "notion" || sourceType === "confluence") return L("페이지", "pages");
  if (sourceType === "website") return L("사이트", "sites");
  return L("저장소", "repositories");
}

/** The "everything" scope choice: what the credential can see, or for a website every domain it lists. */
export function everythingOf(sourceType: string, L: Say): string {
  return sourceType === "website" ? L("연동한 도메인 전체", "Every domain of this integration")
    : L("연동 계정이 볼 수 있는 전체", "Everything the account can see");
}

// "saved": the scope is saved but its plan cannot run now (paused, or it needs a scope review).
export type ScopeStep = "listing" | "selecting" | "saving" | "started" | "saved" | "empty" | "failed";
export type ScopeProgress = { step: ScopeStep; count?: number; unit?: string; code?: string };

const REFRESHING = new Set(["REFRESH_QUEUED", "REFRESH_RUNNING"]);
const sleep = (ms: number) => new Promise(resolve => window.setTimeout(resolve, ms));

/** Lists the target's catalog, freezes the chosen resources and saves them as the approved scope, then
 * starts its first run. ``report`` follows each step; ``stopped`` ends the wait when the reader leaves.
 * ``events`` is a new scope's "scan when it changes"; an existing scope keeps its own. */
export async function applyScope(target: ScopeTarget, mode: ScopeMode, patterns: string[], options: {
  name: string; schedule: number; fullScan?: number | null; events?: boolean; L: Say; report: (progress: ScopeProgress) => void; stopped: () => boolean;
}): Promise<ScopeProgress> {
  const { L, report, stopped } = options;
  const unit = unitOf(target.sourceType, L);
  try {
    report({ step: "listing", unit });
    let view = await send<CatalogView>(`${base(target)}/resources/refresh`, "POST");
    const began = Date.now();
    while (REFRESHING.has(view.reason_code ?? "") || (!view.catalog_snapshot_id && !view.reason_code)) {
      if (stopped()) return { step: "listing", unit };
      if (Date.now() - began > 180_000) return { step: "failed", unit, code: "CATALOG_REFRESH_TIMEOUT" };
      await sleep(1500);
      view = await api<CatalogView>(`${base(target)}/resources?page_size=1`);
    }
    if (!view.catalog_snapshot_id) return { step: "failed", unit, code: view.reason_code ?? "SCOPE_CATALOG_NOT_COLLECTED" };
    report({ step: "selecting", unit });
    const draft = await send<Draft>(`${base(target)}/selection-drafts`, "POST", mode === "named" ? { patterns } : {});
    if (!draft.resource_ids.length) return { step: "empty", unit, count: 0 };
    report({ step: "saving", unit, count: draft.resource_ids.length });
    const current = await readProfiles(target);
    const existing = current.profiles[0];
    const body = {
      ...defaultScopeInput(), expected_version: existing?.version ?? 0, name: options.name,
      change_reason: mode === "named" ? L(`연동 설정에서 지정: ${patterns.join(", ")}`, `Named in the integration settings: ${patterns.join(", ")}`)
        : L(`연동 설정에서 ${everythingOf(target.sourceType, L)}를 지정`, `${everythingOf(target.sourceType, L)}, chosen in the integration settings`),
      catalog_snapshot_id: draft.catalog_snapshot_id, schedule_minutes: options.schedule,
      ...(options.fullScan !== undefined ? { full_scan_minutes: options.fullScan } : {}),
      event_mode: existing ? existing.event_mode ?? "DISABLED" : options.events ? "ENABLED" : "DISABLED",
      selected_roots: draft.resource_ids.map(id => ({ resource_id: id, all_current_objects: true })),
    };
    const profile = existing
      ? await send<SavedProfile>(`scan-scope-profiles/${existing.id}`, "PATCH", body)
      : await send<SavedProfile>(`${base(target)}/scan-scope-profiles`, "POST", body);
    const plan = await send<{ plan_id: string; executable: boolean }>(`scan-scope-profiles/${profile.id}/preview`, "POST");
    if (!plan.executable) return { step: "saved", unit, count: draft.resource_ids.length };
    // A run is always queued: it starts beside other connections' scans as soon as a worker is free.
    await send(`scan-runs`, "POST", { plan_id: plan.plan_id, profile_version: profile.version, mode: "BASELINE" });
    return { step: "started", unit, count: draft.resource_ids.length };
  } catch (reason) {
    return { step: "failed", unit, code: reason instanceof DashboardAPIError ? reason.message.split(":", 1)[0] : "UNREACHABLE" };
  }
}

/** Patterns as typed: commas or new lines between names or paths. */
export function splitPatterns(text: string): string[] {
  return text.split(/[,\n]+/).map(item => item.trim()).filter(Boolean);
}
