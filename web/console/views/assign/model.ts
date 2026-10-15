/* What the owner & team assignment screen derives from the credential records and the IdP directory. */

import { type Person, assignedPerson } from "@/console/people";
import { type CredentialRecord, isExposed, isOpen } from "@/console/records";
import { time } from "@/console/text";

export type Row = { c: CredentialRecord; owner: string | null; person?: Person; team: string | null; status: string; due: string | null; overdue: boolean };
export type Team = { team: string; open: number; unowned: number; waiting: number; overdue: number; done: number; members: number };
export type Filter = "open" | "unowned" | "noteam" | "waiting" | "overdue" | "all";

export const FILTERS: Filter[] = ["unowned", "noteam", "waiting", "overdue", "all"];
/** The team filter for credentials no team has: no team's name can be it (the URL says noteam=1). */
export const NO_TEAM: unique symbol = Symbol("no team");
export type TeamFilter = string | typeof NO_TEAM | null;

/** Every exposed credential with a finding: its owner, the team (the review's, else the owner's, else the owner's
 * IdP department), the review state and whether its due date has passed. */
export function assignRows(records: CredentialRecord[], _people: Person[] | undefined, now = Date.now()): Row[] {
  return records.filter(c => isExposed(c) && c.finding_id).map(c => {
    const owner = c.owner?.name ?? null;
    const person = assignedPerson(c);
    const status = c.response?.state ?? c.review?.status ?? "OPEN";
    const due = c.review?.due_at ?? null;
    return { c, owner, person, team: c.review?.assigned_team || c.owner?.team || person?.department || null, status, due,
      overdue: Boolean(due) && status !== "CLOSED" && (time(due) ?? Infinity) < now };
  });
}

/** One line per team the rows name (no team last): what still needs action there, and its IdP members. */
export function teamsOf(rows: Row[], people: Person[] | undefined): Team[] {
  const out = new Map<string, Team>();
  for (const row of rows) {
    const key = row.team ?? "";
    const entry = out.get(key) ?? { team: key, open: 0, unowned: 0, waiting: 0, overdue: 0, done: 0, members: 0 };
    if (isOpen(row.c)) {
      entry.open++;
      if (!row.owner) entry.unowned++;
      if (row.status === "WAITING_OWNER") entry.waiting++;
      if (row.overdue) entry.overdue++;
    } else entry.done++;
    out.set(key, entry);
  }
  for (const person of people ?? []) {
    const entry = person.department && person.state !== "DEPARTED" ? out.get(person.department) : undefined;
    if (entry) entry.members++;
  }
  return [...out.values()].sort((a, b) => Number(!a.team) - Number(!b.team) || b.open - a.open || a.team.localeCompare(b.team));
}

/** The rows one filter, team and search show. */
export function shownRows(rows: Row[], filter: Filter, team: TeamFilter, needle: string, name: (c: CredentialRecord) => string): Row[] {
  const q = needle.trim().toLowerCase();
  return rows.filter(row => (filter === "all" || isOpen(row.c))
    && (filter !== "unowned" || !row.owner) && (filter !== "noteam" || !row.team) && (filter !== "waiting" || row.status === "WAITING_OWNER")
    && (filter !== "overdue" || row.overdue) && (team === null || (team === NO_TEAM ? !row.team : row.team === team))
    && (!q || [name(row.c), row.owner, row.person?.name, row.team, ...row.c.exposures.map(e => e.resource_name)].some(value => value?.toLowerCase().includes(q))));
}

/** The ownership-review route takes at most 100 findings a request. */
export function batches<T>(items: T[], size = 100): T[][] {
  const out: T[][] = [];
  for (let start = 0; start < items.length; start += size) out.push(items.slice(start, start + size));
  return out;
}
