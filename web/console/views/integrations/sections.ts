/* The integrations page's two kinds of connection -- accounts and issuance inventories, and content scan
 * locations -- as rules over the catalog and the connection list: which catalog card says 연동됨, which
 * section a connection is listed in, and what each of its features is doing there. */

import type { Say } from "@/console/text";
import { capName, featureName } from "@/console/views/integrations/copy";
import {
  checked, checkItems, type CollectionEntry, type Descriptor, forCollectionEntry, type HealthItem, healthOf, inEntryView, label,
  planFields, type ProviderConnection, type Purpose, PURPOSE_ORDER, purposesForEdition, rowState, type RowState, typeChoices, valuesOf,
} from "@/console/views/integrations/model";
import { scopeTargets } from "@/console/views/integrations/scope";

/** The connected-services sections in page order: accounts and inventories, then content scan locations. */
export const SECTIONS: CollectionEntry[] = ["account", "exposure"];

/** A feature that runs now: an active connection with its plan, not switched off. */
export const live = (c: ProviderConnection, p: Purpose) => c.status === "ACTIVE" && Boolean(c.plans[p]) && c.feature_enabled?.[p] !== false;
/** Some feature of the entry (any feature without one) runs on the connection. */
export const liveIn = (c: ProviderConnection, entry?: CollectionEntry) => PURPOSE_ORDER.some(p => inEntryView(p, entry) && live(c, p));

/** The account features an edition offers a connection. */
export const accountFeaturesFor = (d: Descriptor, edition: string) => purposesForEdition(forCollectionEntry(d, "account"), edition);

/** The account card's features: those a new-setup edition offers. None: the provider has no account card. */
export function accountFeatures(d: Descriptor): Purpose[] {
  const offered = new Set(d.editions.filter(e => e.new_setup !== false).flatMap(e => accountFeaturesFor(d, e.id)));
  return PURPOSE_ORDER.filter(p => offered.has(p));
}

/** The editions an account feature is limited to, as "Enterprise 전용: 발급 목록·조치" (an edition may be a product, not
 * a plan); null when every new-setup edition offers them all. */
export function accountNote(d: Descriptor, L: Say): string | null {
  const editions = d.editions.filter(e => e.new_setup !== false);
  const groups = new Map<string, Purpose[]>();
  for (const p of accountFeatures(d)) {
    const on = editions.filter(e => accountFeaturesFor(d, e.id).includes(p));
    if (on.length === editions.length) continue;
    const names = on.map(e => label(e, L)).join(", ");
    groups.set(names, [...(groups.get(names) ?? []), p]);
  }
  return groups.size ? [...groups].map(([names, purposes]) => L(`${names} 전용: ${purposes.map(p => capName(p, L)).join("·")}`,
    `${names} only: ${purposes.map(p => capName(p, L)).join(" · ")}`)).join(" ") : null;
}

/** Whether the content card can be opened: an owner to reuse or, except for AWS (whose S3 is read through the
 * account's role), a new-setup method that signs in first and serves content scans. */
export function contentStartable(d: Descriptor, owners: number): boolean {
  return owners > 0 || (d.provider !== "aws" && d.auth_methods.some(m => Boolean(m.auth_first) && m.new_setup !== false && m.purposes.includes("exposure")));
}

/** A credential owner the content card can reuse: one that scans content already, or a connected account. */
export const contentOwner = (c: ProviderConnection) => !c.purposes.includes("remediation") && (c.purposes.includes("exposure")
  || (c.status !== "DISABLED" && (c.status === "ACTIVE" || c.checks.authentication_only === true)));

/** The purposes of a connection in a section: checked or selected (``purposes``), or planned. */
export const sectionPurposes = (c: ProviderConnection, entry: CollectionEntry) =>
  PURPOSE_ORDER.filter(p => inEntryView(p, entry) && (c.purposes.includes(p) || c.plans[p] !== undefined));

/** The sections a connection is listed in. One without features (an authentication-only owner) sits under the
 * account section when its edition offers account features, else under content. */
export function sectionsOf(c: ProviderConnection, d: Descriptor | undefined): CollectionEntry[] {
  const found = SECTIONS.filter(entry => sectionPurposes(c, entry).length);
  if (found.length) return found;
  return [!d || accountFeaturesFor(d, c.edition).length ? "account" : "exposure"];
}

/** A connection the account card offers: listed under accounts, or of an edition with account features. */
export const accountOwner = (c: ProviderConnection, d: Descriptor | undefined) => sectionsOf(c, d).includes("account") || Boolean(d && accountFeaturesFor(d, c.edition).length);

/** The connection as one section sees it: that section's features, plans, checks and owned records. The content
 * section also has the records its scans read through (an AWS account, whatever feature made it). */
export function sectionView(c: ProviderConnection, entry: CollectionEntry): ProviderConnection {
  function pick<T>(record: Partial<Record<Purpose, T>> | undefined) {
    return record && Object.fromEntries(Object.entries(record).filter(([p]) => inEntryView(p as Purpose, entry))) as Partial<Record<Purpose, T>>;
  }
  const scanned = new Set(entry === "exposure" ? scopeTargets(c).map(target => target.id) : []);
  return { ...c, purposes: c.purposes.filter(p => inEntryView(p, entry)), plans: pick(c.plans) ?? {}, feature_enabled: pick(c.feature_enabled),
    children: c.children.filter(child => inEntryView(child.purpose, entry) || scanned.has(child.id)), checks: { ...c.checks, results: pick(c.checks.results) ?? {} } };
}

/** Whether a section row's "Collect now" has anything to run: a server collection of its features, or for content a
 * scan target of a running exposure scan (collectConnection reads the same). */
export function runnableIn(c: ProviderConnection, entry: CollectionEntry): boolean {
  return c.children.some(child => inEntryView(child.purpose, entry) && c.feature_enabled?.[child.purpose] !== false && ["content", "metadata", "coverage"].includes(child.kind))
    || (entry === "exposure" && live(c, "exposure") && scopeTargets(c).length > 0);
}

export type BadgeState = "on" | "off" | "missing" | "pending";
/** ``missing``: the permissions the last check did not grant, for a feature it held back. */
export type Badge = { purpose: Purpose; state: BadgeState; count?: number; missing: string[] };

/** What a feature is doing: running, switched off (or the connection stopped), held back by its check, or not
 * started yet. */
export function badgeState(c: ProviderConnection, p: Purpose): BadgeState {
  if (c.plans[p]) return c.feature_enabled?.[p] === false || c.status === "DISABLED" ? "off" : c.status === "ACTIVE" ? "on" : "pending";
  const status = c.checks.results?.[p]?.status;
  return status && status !== "PASSED" ? "missing" : "pending";
}

/** How many of each feature's things a row counts: the inventory's types turned on, and the content locations
 * in approved scope (``scoped``, as Results reads it), not the kinds of source a scan reads. */
export function sectionCounts(d: Descriptor | undefined, c: ProviderConnection, scoped?: number): Partial<Record<Purpose, number>> {
  if (!d) return { exposure: scoped };
  const fields = planFields(d, "inventory", c.edition, c.target);
  return { inventory: typeChoices(d, c.edition, c.target, fields, valuesOf(fields, c.plans.inventory ?? {})).filter(choice => choice.on).length, exposure: scoped };
}

/** One badge per feature of the section. */
export function badges(c: ProviderConnection, entry: CollectionEntry, d: Descriptor | undefined, L: Say, counts: Partial<Record<Purpose, number>> = {}): Badge[] {
  return sectionPurposes(c, entry).map(p => {
    const state = badgeState(c, p);
    const names = state === "missing" ? checkItems(c, [p], d).filter(item => item.status !== "GRANTED").map(item => {
      const permission = d?.purposes[p]?.permissions?.find(entry => entry.id === item.permission);
      return permission ? label(permission, L) : item.permission;
    }) : [];
    return { purpose: p, state, count: counts[p], missing: [...new Set(names)] };
  });
}

export type SectionState = RowState & { choose?: boolean };
/** Fixes that act on the whole connection: shown on its first section row only. */
export const CONNECTION_FIXES: Partial<Record<NonNullable<RowState["fix"]>, true>> = { resume: true, reauth: true, credential: true };

/** A section row's status: the connection's own problems (stopped, setup, sign-in, expiry, shared credential),
 * else the section's features. An authentication-only owner listed under content has yet to choose locations. */
export function sectionState(c: ProviderConnection, entry: CollectionEntry, health: HealthItem[] | undefined, L: Say, d?: Descriptor, now = Date.now()): SectionState {
  if (entry === "exposure" && c.status !== "DISABLED" && c.checks.authentication_only === true && !Object.keys(c.plans).length)
    return { tone: "setup", label: L("계정 인증만 완료", "Account sign-in only"), note: L("검사할 위치를 아직 고르지 않았습니다", "No scan location chosen yet"), choose: true };
  // The connection's own problems come from all of its records: a sign-in to renew on the content side is the account
  // row's (first row's) fix too.
  const whole = rowState(c, healthOf(c, health), L, now, d);
  const checking = Boolean(c.checks.job_id && !checked(c) && c.checks.requested_at);
  if (c.status !== "ACTIVE" || checking || c.sign_in_problem || (whole.fix && CONNECTION_FIXES[whole.fix])) return whole;
  const view = sectionView(c, entry);
  const state = rowState(view, healthOf(view, health), L, now, d);
  if (state.fix && CONNECTION_FIXES[state.fix]) return state;
  const list = badges(c, entry, d, L);
  const held = list.filter(b => b.state === "missing");
  if (held.length) {
    const on = list.some(b => b.state === "on");
    const names = held.map(b => `${featureName(b.purpose, L)}${b.missing.length ? ` (${b.missing.join(", ")})` : ""}`).join(", ");
    return { tone: on ? "partial" : "warn", label: on ? L("일부 기능 권한 부족", "Some features lack access") : L("권한 부족", "Access missing"),
      note: L(`권한이 없어 시작하지 않았습니다: ${names}`, `Not started for missing access: ${names}`), fix: "recheck" };
  }
  if (list.length && list.every(b => b.state === "pending")) return { tone: "setup", label: L("설정 중", "Setting up"), note: L("아직 시작하지 않은 기능입니다", "Not started yet") };
  return state;
}
