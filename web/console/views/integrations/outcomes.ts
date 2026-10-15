/* What an access check found for each chosen feature: ready, or held with exactly what is missing (permission,
 * target, subject, detail). Display only: the server's own gate (permissions.require) still decides select and
 * complete, and a held feature is only ever left out, never let through. */
import { permissionsFor, type CheckItem, type Descriptor, type Purpose, type PurposeCheck, type Values } from "./model";

/** A check answer as the draft gives it: answers for a multi-target draft carry their target. */
export type Answer = CheckItem & { target_id?: string };
/** A server blocker (permissions.blockers): an answer that is not GRANTED, a subject the check did not answer, or,
 * with no purpose, evidence that is missing or stale for the whole selection. */
export type Blocker = { purpose?: Purpose; permission?: string; status: string; detail?: string; subject?: string; target_id?: string };
export type Missing = { permission?: string; status: string; detail?: string; subject?: string; target_id?: string };
/** ``passing``: the feature's selected targets whose required access was all granted. */
export type FeatureOutcome = { purpose: Purpose; ok: boolean; missing: Missing[]; passing: string[] };
export type OutcomeTarget = { id: string; target: Record<string, unknown> };

const pick = (item: Missing): Missing => Object.fromEntries(Object.entries({ permission: item.permission, status: item.status,
  detail: item.detail, subject: item.subject, target_id: item.target_id }).filter(([, value]) => value !== undefined)) as Missing;

export function featureOutcomes(d: Descriptor, method: string, purposes: Purpose[], targetsOf: (p: Purpose) => OutcomeTarget[],
  planOf: (p: Purpose) => Values, results: Partial<Record<Purpose, PurposeCheck>> | undefined, blockers: Blocker[]): FeatureOutcome[] {
  // Stale or missing evidence answers for no feature: nothing is ready until the selection is checked again.
  const stale = blockers.find(b => b.detail === "PERMISSION_CHECK_REQUIRED");
  return purposes.map(p => {
    if (stale) return { purpose: p, ok: false, missing: [pick(stale)], passing: [] };
    const targets = targetsOf(p);
    const answers = (results?.[p]?.items ?? []) as Answer[];
    const failed = new Map<string, Missing[]>();
    for (const t of targets) {
      const out: Missing[] = [];
      for (const permission of permissionsFor(d, p, method, t.target, planOf(p)).filter(item => item.required !== false)) {
        // A single-target draft's answers name no target; a multi-target draft's name each one.
        const found = answers.filter(a => a.permission === permission.id && (a.target_id ?? t.id) === t.id);
        if (!found.length) out.push({ permission: permission.id, status: "NOT_REPORTED", detail: "NOT_CHECKED", target_id: t.id });
        out.push(...found.filter(a => a.status !== "GRANTED").map(a => pick({ ...a, target_id: a.target_id ?? t.id })));
      }
      if (out.length) failed.set(t.id, out);
    }
    const server = blockers.filter(b => !b.purpose || b.purpose === p).map(pick);
    // A blocker naming no target (a subject the check did not answer) cannot be pinned on one of several targets.
    const unplaced = targets.length > 1 && server.some(b => !b.target_id);
    const passing = unplaced ? [] : targets.filter(t => !failed.has(t.id) && !server.some(b => (b.target_id ?? t.id) === t.id)).map(t => t.id);
    const missing = server.length ? server : [...failed.values()].flat();
    if (!targets.length && !missing.length) missing.push({ status: "MISSING", detail: "ONBOARDING_EACH_FEATURE_NEEDS_TARGET" });
    return { purpose: p, ok: !missing.length, missing, passing };
  });
}
