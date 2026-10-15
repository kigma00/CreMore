/* One setup journey may need several credential owners. These groups only guide the UI;
 * each existing onboarding endpoint still authorizes its own credential and exact scope. */
import { methodsFor, purposesOf, purposesForEdition, serves, type Descriptor, type Purpose } from "./model";

export type SetupGroup = { method: string; edition: string; purposes: Purpose[] };
export type SetupJourney = {
  provider: string; edition: string; requested: Purpose[]; pending: SetupGroup[];
  current?: SetupGroup; completed: { id: string; purposes: Purpose[] }[];
  expires: number;
};

/** Use the signed-in method first, then the smallest number of other methods. Acting
 * credentials always have a separate group, even when their method has the same name. */
export function setupGroups(d: Descriptor, selected: Purpose[], edition: string, preferred: string): SetupGroup[] {
  let left = [...new Set(selected)].filter(p => purposesForEdition(d, edition).includes(p));
  const out: SetupGroup[] = [];
  const take = (method: string, selectedEdition: string, allowActing: boolean) => {
    const offered = methodsFor(d, [], selectedEdition).find(m => m.id === method);
    const purposes = left.filter(p => offered && serves(offered, p, selectedEdition) && (p !== "remediation" || allowActing));
    if (purposes.length) { out.push({ method, edition: selectedEdition, purposes }); left = left.filter(p => !purposes.includes(p)); }
  };
  const editions = [edition];
  take(preferred, edition, left.length === 1 && left[0] === "remediation");
  while (left.some(p => p !== "remediation")) {
    const method = editions.flatMap(e => methodsFor(d, [], e).map(m => ({ m, edition: e, count: left.filter(p => p !== "remediation" && serves(m, p, e)).length })))
      .sort((a, b) => b.count - a.count)[0];
    if (!method?.count) break;
    take(method.m.id, method.edition, false);
  }
  if (left.includes("remediation")) {
    const method = editions.flatMap(e => methodsFor(d, ["remediation"], e).map(m => ({ m, edition: e })))[0];
    if (method) out.push({ method: method.m.id, edition: method.edition, purposes: ["remediation"] });
  }
  return out;
}

const storageKey = (provider: string) => `cremore:setup:${provider}`;
/** Only bounded feature IDs and connection references survive a provider redirect.
 * No token, target payload, app key, or other credential is stored here. */
export function readJourney(d: Descriptor): SetupJourney | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(storageKey(d.provider)) ?? "null");
    const validPurposes = (items: unknown): items is Purpose[] => Array.isArray(items) && items.length <= 5
      && items.every(p => typeof p === "string" && purposesOf(d).includes(p as Purpose));
    const group = (v: SetupGroup) => v && typeof v.method === "string" && validPurposes(v.purposes)
      && v.edition === value.edition && methodsFor(d, v.purposes, v.edition).some(m => m.id === v.method)
      && (!v.purposes.includes("remediation") || v.purposes.length === 1);
    if (!value || value.provider !== d.provider || !d.editions.some(e => e.id === value.edition)
      || typeof value.expires !== "number" || value.expires <= Date.now() || value.expires > Date.now() + 1800000
      || !validPurposes(value.requested) || value.requested.some((p: Purpose) => !purposesForEdition(d, value.edition).includes(p))
      || !Array.isArray(value.pending) || value.pending.length > 5 || !value.pending.every(group)
      || (value.current && !group(value.current)) || !Array.isArray(value.completed) || value.completed.length > 5
      || !value.completed.every((item: { id: string; purposes: Purpose[] }) => /^[0-9a-f-]{36}$/i.test(item.id) && validPurposes(item.purposes))) return null;
    const copyGroup = (v: SetupGroup): SetupGroup => ({ method: v.method, edition: v.edition, purposes: [...v.purposes] });
    return { provider: d.provider, edition: value.edition, expires: value.expires, requested: [...value.requested],
      pending: value.pending.map(copyGroup), ...(value.current ? { current: copyGroup(value.current) } : {}),
      completed: value.completed.map((item: { id: string; purposes: Purpose[] }) => ({ id: item.id, purposes: [...item.purposes] })) };
  } catch { return null; }
}

export function rememberJourney(provider: string, journey: SetupJourney | null) {
  try {
    if (journey) sessionStorage.setItem(storageKey(provider), JSON.stringify(journey));
    else sessionStorage.removeItem(storageKey(provider));
  } catch { /* The open journey still works when session storage is unavailable. */ }
}
