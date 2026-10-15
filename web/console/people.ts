/* The people the IdP integrations name (GET /api/v1/people, analysts and up): what a name or an email
 * stands for, where the person works, how to reach them and whether they have left. */

import { useApi } from "@/console/data";
import type { CredentialRecord } from "@/console/records";

export type Person = {
  id: string; name: string; email: string | null; department: string | null; title: string | null;
  state: "ACTIVE" | "DEPARTED" | "PENDING" | "UNKNOWN" | string;
  sources: { provider: string; connection_id: string; state: string }[];
  /** Every IdP user this person is; the departed-owner check names people by these. */
  refs?: string[];
  person_ref?: string; selectable?: boolean; reason?: string | null;
};
export type DirectoryPerson = Person & { person_ref: string; selectable: boolean };
export type DirectorySource = {
  connection_id: string; provider: string; name?: string | null; status: string; usable: boolean; observed_at?: string | null;
  provider_connection_id?: string | null; schedule_minutes?: number; collection_status?: string | null;
};
export type DirectoryState = { status: string; usable: boolean; reason?: string | null; observed_at?: string | null; sources?: DirectorySource[] };
export type People = { items: Person[]; total: number; next_cursor?: string | null; directory?: DirectoryState };
export type DirectoryPage = { items: DirectoryPerson[]; total: number; next_cursor: string | null; directory: DirectoryState };

export function peoplePath(query = "", cursor?: string | null): string {
  const params = new URLSearchParams({ q: query.trim(), limit: "25" });
  if (cursor) params.set("cursor", cursor);
  return `people?${params}`;
}

/** Selection requires server-confirmed identity and availability, never a typed name or email. */
export function selectablePerson(person: DirectoryPerson | null | undefined): person is DirectoryPerson {
  return !!person && person.selectable === true && !!person.person_ref && person.state === "ACTIVE" && !!person.email;
}

/** Display the server's current owner; a historical ticket recipient cannot restore an unassignment. */
export function assignedPerson(c: CredentialRecord): Person | undefined {
  const profile = c.owner;
  if (!profile?.person_ref) return undefined;
  return { id: profile.person_ref, person_ref: profile.person_ref, name: profile.name ?? profile.email ?? "", email: profile.email ?? null,
    department: profile.department ?? null, title: profile.title ?? null, state: profile.state ?? "UNKNOWN", sources: [] };
}

/** An approved team Slack channel as the routing names it (phase 2). */
export type RoutingChannel = { channel_id: string; name: string; is_private: boolean };
export type ResponderRouting = {
  version: number; status: "READY" | "UNASSIGNED" | "AMBIGUOUS" | "UNAVAILABLE"; manual_email_allowed: boolean;
  assignment: { person_ref: string; person?: DirectoryPerson; team?: string | null; basis?: string; updated_at?: string } | null;
  /** `slack_channel`: the approved channel a responsibility rule names, recommended with its person and team. */
  recommendations: { person: DirectoryPerson; basis: string; account_ref?: string; rule_id?: string; team?: string | null; slack_channel?: RoutingChannel | null }[];
  targets: { kind: "location" | "account"; key: string; label: string; rule: { version: number; person_ref: string; team?: string | null; channel_id?: string | null; updated_at?: string } | null }[];
  /** The one approved channel the finding's rules name; null when they name none or several. */
  slack_channel?: RoutingChannel | null;
};

export const PEOPLE_PATH = "people?limit=500";

export function usePeople(enabled: boolean) {
  return useApi<People>(enabled ? PEOPLE_PATH : null);
}

/** The person a name or an email names: an email first, then an exact name (ignoring case). */
export function personOf(people: Person[] | undefined, value: string | null | undefined): Person | undefined {
  const key = value?.trim().toLowerCase();
  if (!people || !key) return undefined;
  return people.find(person => person.email?.toLowerCase() === key) ?? people.find(person => person.name.toLowerCase() === key);
}

/** A display name or provider login is not an IdP address. Only explicit addresses or exact person refs resolve. */
export function addressesOf(people: Person[] | undefined, names: string[]): string[] {
  return Array.from(new Set(names.map(name => people?.find(person => person.person_ref === name || person.refs?.includes(name))?.email ?? (name.includes("@") ? name.trim() : ""))
    .filter(Boolean)));
}

/* What the code hosts say about a finding's exposed files (GET findings/{id}/context, analysts and up):
 * each file's CODEOWNERS owners and last author, and who can read each repository. */
export type ContextPerson = { login: string; name: string | null; role: string | null; read_access?: "REPORTED" | "UNKNOWN";
  principal_id?: string; principal_kind?: "USER" | "GROUP" | "SERVICE_PRINCIPAL" | "PUBLIC" | "AUTHENTICATED" | "POLICY" | "UNKNOWN";
  permission?: string | null; effect?: "ALLOW" | "DENY" | "RESTRICT" | "UNKNOWN" };
export type ContextRepository = {
  access_key?: string; source_connection_id?: string | null; source_label?: string | null;
  source_type: string; repository: string; status: string; basis: string | null;
  people?: ContextPerson[]; truncated?: boolean; evidence_kind?: string; observed_at?: string | null;
  completeness?: "COMPLETE" | "PARTIAL" | "UNKNOWN" | "UNSUPPORTED";
  limitations?: string[]; visibility?: "PUBLIC" | "INTERNAL" | "PRIVATE" | "UNKNOWN";
};
export type FindingContext = {
  status: "NOT_COLLECTED" | "COMPLETE" | "PARTIAL" | "UNSUPPORTED" | "FAILED";
  locations: {
    exposure_id: string; source_type: string; repository: string; path: string; commit: string;
    access_key?: string; source_connection_id?: string | null; source_label?: string | null; context_status?: string;
    codeowners: { status: string; path?: string; owners?: { owner: string; kind: string; line: number }[] };
    author: { status: string; name?: string | null; login?: string | null; email?: string | null; at?: string | null; commit?: string | null };
  }[];
  repositories: ContextRepository[];
  reasons: string[]; collected_at: string | null; job_id?: string; job_status?: string;
  location_count?: number; queried_locations?: number; unqueried_locations?: number; omitted_locations?: number;
};

/** Join only an exact source-bound access key. Legacy names alone cannot identify a code host. */
export function locationAccess(context: FindingContext, place: FindingContext["locations"][number]): ContextRepository | undefined {
  if (!place.access_key || !place.source_connection_id) return undefined;
  const matches = context.repositories.filter(repository => repository.access_key === place.access_key
    && repository.source_connection_id === place.source_connection_id && repository.source_type === place.source_type
    && repository.repository === place.repository);
  return matches.length === 1 ? matches[0] : undefined;
}

export function repositoryPeople(repository: ContextRepository | undefined): ContextPerson[] {
  return repository && (repository.status === "OBSERVED" || repository.completeness === "PARTIAL" && repository.observed_at)
    ? repository.people ?? [] : [];
}

export function locationAccessStatus(place: FindingContext["locations"][number], repository: ContextRepository | undefined): string {
  if (repository) return repository.status;
  if (place.context_status && place.context_status !== "OBSERVED") return place.context_status;
  return !place.access_key || !place.source_connection_id ? "REFRESH_REQUIRED" : "UNAVAILABLE";
}

/** Provider account rows retain connection and repository identity; display names never merge identities. */
export function accessPeople(context: FindingContext | undefined): (ContextPerson & { repository: string; basis: string | null; access_key: string; source_connection_id: string })[] {
  const out = new Map<string, ContextPerson & { repository: string; basis: string | null; access_key: string; source_connection_id: string }>();
  for (const repository of context?.repositories ?? []) {
    if (!repository.access_key || !repository.source_connection_id) continue;
    if (!context?.locations.some(place => locationAccess(context, place) === repository)) continue;
    for (const person of repositoryPeople(repository)) {
      const key = `${repository.access_key}:${person.login.toLowerCase()}`;
      if (!out.has(key)) out.set(key, { ...person, repository: repository.repository, basis: repository.basis,
        access_key: repository.access_key, source_connection_id: repository.source_connection_id });
    }
  }
  return Array.from(out.values());
}

/** One row per location/account; empty, partial and unsupported observations retain their provenance. */
export function accessRows(context: FindingContext): string[][] {
  const rows = [["source_type", "source_connection_id", "source_label", "access_key", "exposure_id", "repository", "path", "status",
    "completeness", "visibility", "login", "name", "role", "read_access", "basis", "evidence_kind", "observed_at", "limitations",
    "location_count", "queried_locations", "unqueried_locations", "omitted_locations", "principal_id", "principal_kind", "permission", "effect"]];
  for (const place of context.locations) {
    const repository = locationAccess(context, place);
    const people = repositoryPeople(repository);
    for (const person of people.length ? people : [undefined]) {
      rows.push([place.source_type, place.source_connection_id ?? "", place.source_label ?? "", place.access_key ?? "", place.exposure_id,
        place.repository, place.path, locationAccessStatus(place, repository),
        repository?.completeness ?? "UNKNOWN", repository?.visibility ?? "UNKNOWN", person?.login ?? "", person?.name ?? "", person?.role ?? "",
        person?.read_access ?? "UNKNOWN", repository?.basis ?? "", repository?.evidence_kind ?? "", repository?.observed_at ?? "",
        (repository?.limitations ?? []).join(";"), ...[context.location_count, context.queried_locations,
          context.unqueried_locations, context.omitted_locations].map(value => value === undefined ? "" : String(value)),
        person?.principal_id ?? "", person?.principal_kind ?? "UNKNOWN", person?.permission ?? "", person?.effect ?? "UNKNOWN"]);
    }
  }
  return rows;
}
