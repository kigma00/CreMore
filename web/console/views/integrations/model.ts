/* Integrations: the provider catalog the wizard is built from, the provider connections it makes,
 * and how a connection's owned records are doing. Everything here is data and rules; the screens
 * are in page.tsx and wizard.tsx.
 *
 * The catalog (GET provider-connections/catalog) is the one source of what a provider offers:
 * editions, target fields, purposes with their permission checklists and step 4 plan options, and
 * auth methods in recommended order. These helpers apply its rules the way the server does
 * (cremore/onboarding/catalog.py, service.py), so the wizard never offers what the server refuses. */

import type { CredentialRecord } from "@/console/records";
import type { Say } from "@/console/text";

export type Purpose = "exposure" | "inventory" | "vault" | "identity" | "remediation";
// The order the wizard shows features in: what a provider issued, then where values leaked; last, the credential that
// acts on approved plans.
export const PURPOSE_ORDER: Purpose[] = ["inventory", "exposure", "vault", "identity", "remediation"];

export type FieldKind = "text" | "name" | "url" | "id" | "list" | "secret" | "multiline" | "choice" | "choices" | "number" | "bool";
export type Option = { id: string; label: string; label_ko: string };
export type FieldSpec = {
  product?: boolean;
  schedule?: boolean;
  name: string; label: string; label_ko: string; kind?: FieldKind; required?: boolean; optional?: boolean;
  editions?: string[]; hint?: string; when?: Record<string, string[]>; default?: unknown; options?: Option[];
  description?: string; description_ko?: string;
  /** A plan field's default in these editions, in place of ``default`` (planFields applies it). */
  edition_defaults?: Record<string, unknown>;
  target_default?: string;
  min?: number; max?: number; secret?: boolean; public?: boolean;
};
/** ``option``: needed only while that bool plan choice is on, ``unless``: only while it is off or not offered (the
 * check still answers it). */
export type Permission = { id: string; label: string; label_ko: string; methods?: string[]; when?: Record<string, string[]>; option?: string; unless?: string; nonempty?: string; required?: boolean };
export type Renewal = "AUTOMATIC" | "EXPIRES" | "ROTATES" | "REFRESH" | "NONE";
export type Method = {
  id: string; label: string; label_ko: string; renewal: Renewal; purposes: Purpose[]; fields?: FieldSpec[];
  advanced?: boolean; editions?: string[]; reference?: boolean; reference_keys?: string[]; flow?: string;
  /** The editions this method serves one of its purposes in, when narrower than the method's (catalog.methods_for). */
  purpose_editions?: Partial<Record<Purpose, string[]>>;
  /** CreMore makes this credential itself (a Microsoft app certificate); its fields only say what it is for. */
  generated?: boolean;
  auth_first?: { context: string[] };
  /** False keeps this method available only to its existing credential owner. */
  new_setup?: boolean;
  /** Derived for account entry: authenticate now, select content separately. */
  authentication_only?: boolean;
};
export type Category = "code" | "cloud" | "saas" | "vault" | "identity";
// The key metadata of an issued credential, in the order an inventory type's support string gives them.
export const INVENTORY_FIELDS = ["id", "name", "created", "expires", "scopes", "creator", "owner", "last_used", "state"] as const;
export type InventoryField = typeof INVENTORY_FIELDS[number];
/** How a type is collected: always (where ``when``/``editions`` hold), or through a plan option. */
export type Binding = { always?: boolean; field?: string; option?: string; when?: Record<string, string[]>; editions?: string[] };
export type InventoryType = {
  id: string; label: string; label_ko: string; description?: string; description_ko?: string; permission?: string;
  credential_type?: string; editions?: string[]; when?: Record<string, string[]>; plan?: Binding[];
  snapshot_only?: boolean; export_type?: string;
  support: string; reasons: Partial<Record<InventoryField, [string, string]>>;
  /** The collections whose listed items are this type (their provider), among other conditions. */
  match?: { provider?: string | string[] }[];
};
/** What an exposure scan reads, as the provider declares it. */
export type ScanItem = {
  id: string; label: string; label_ko: string; description?: string; description_ko?: string; editions?: string[];
  when?: Record<string, string[]>;
};
export type Descriptor = {
  provider: string; label: string; label_ko: string; category: Category;
  /** New connections are made with this provider instead; existing ones keep running. */
  replaced_by?: string;
  /** Started from another screen, not the service grid ("domains": the domain verification window). */
  entry?: string;
  editions: (Option & { origin?: boolean; new_setup?: boolean })[]; target?: FieldSpec[];
  purposes: Partial<Record<Purpose, { editions?: string[]; permissions?: Permission[]; plan?: FieldSpec[]; types?: InventoryType[]; scans?: ScanItem[] }>>;
  auth_methods: Method[];
};
/** On a team install, the IdP people sign in with: the only people directory to connect (cremore.onboarding.sign_in).
 * ``provider`` null: no IdP CreMore reads people from names the issuer. The catalog says null on a single operator's
 * install. */
/** ``exempt``: providers whose people link stays open (GitHub ties its logins to the IdP's people). */
export type SignInIdp = { issuer: string; provider: string | null; target: Record<string, string> | null; exempt?: string[] };
export type Catalog = { purposes: Purpose[]; providers: Descriptor[]; sign_in_idp?: SignInIdp | null; schedules_allowed?: boolean };
export const CATALOG_PATH = "provider-connections/catalog";

/** Close to how the provider modules keep a target value (host in lower case, no scheme, default port or trailing
 * slash): an early hint only, the API compares exactly. */
const plainValue = (value: unknown) => String(value ?? "").trim().toLowerCase().replace(/^https:\/\//, "").replace(/\/+$/, "").replace(/:443$/, "");

/** Why a new connection of ``d`` may not read people on this install, or null. ``target`` null asks about the
 * provider alone (a menu of directories); otherwise the target must be the sign-in IdP's. The API decides. */
export function peopleDirectoryBlock(catalog: Catalog, d: Descriptor, target: Record<string, unknown> | null, L: Say): string | null {
  const signIn = catalog.sign_in_idp;
  if (!signIn || !d.purposes.identity || (signIn.exempt ?? []).includes(d.provider)) return null;
  if (!signIn.provider) return L(`로그인 IdP(${signIn.issuer})를 CreMore가 사람 목록을 읽는 IdP로 알아보지 못해, 팀 설치에서는 사람 목록을 연결하지 않습니다.`,
    `CreMore cannot read people from the sign-in IdP (${signIn.issuer}), so a team install connects no people directory.`);
  const idp = catalog.providers.find(item => item.provider === signIn.provider);
  const idpName = idp ? label(idp, L) : signIn.provider;
  if (d.provider !== signIn.provider && d.replaced_by !== signIn.provider) {
    return L(`팀 설치의 사람 목록은 로그인에 쓰는 IdP(${idpName})로만 연결합니다.`, `A team install connects people only from the IdP people sign in with (${idpName}).`);
  }
  const differs = target ? Object.entries(signIn.target ?? {}).find(([name, value]) => plainValue(target[name]) !== plainValue(value)) : undefined;
  if (!differs) return null;
  const field = d.target?.find(item => item.name === differs[0]);
  const named = field ? label(field, L) : differs[0];
  return L(`사람 목록은 로그인에 쓰는 IdP와 같아야 합니다: ${named} ${differs[1] || "(비움)"}`,
    `The people directory must be the IdP people sign in with: ${named} ${differs[1] || "(empty)"}`);
}
export const CONNECTIONS_PATH = "provider-connections";

export type CheckStatus = "GRANTED" | "MISSING" | "NOT_REPORTED" | "ERROR";
export type CheckItem = { permission: string; status: CheckStatus; detail?: string; subject?: string };
export type PurposeCheck = { status: "PASSED" | "MISSING" | "ERROR" | "NOT_REPORTED"; items: CheckItem[] };
export type ConnectionStatus = "DRAFT" | "CHECKING" | "CHECKED" | "ACTIVE" | "DISABLED";
export type Child = {
  kind: string; id: string; purpose: Purpose; name?: string | null; state?: string; revision?: number;
  account_id?: string; access?: string; validation?: string; source_type?: string; provider?: string;
};
export type ProviderConnection = {
  id: string; provider: string; edition: string; name: string; status: ConnectionStatus; revision: number;
  purposes: Purpose[]; target: Record<string, unknown>; plans: Partial<Record<Purpose, Record<string, unknown>>>;
  feature_enabled?: Partial<Record<Purpose, boolean>>;
  auth_method: string; renewal: Renewal | null;
  /** ``shared_with``: integrations on the other side (acting / collecting) whose last check found this very credential. */
  credential: { roles: string[]; reference: boolean; shared_with?: { id: string; name: string }[] };
  checks: { results: Partial<Record<Purpose, PurposeCheck>>; checked_at: string | null; requested_at: string | null;
    job_id: string | null; stale: boolean; error: string | null; renewal?: Renewed | null; authentication_only?: boolean;
    requested_plans?: Partial<Record<Purpose, Record<string, unknown>>>; blockers?: CheckItem[] };
  children: Child[];
  created_by?: string; created_at?: string; updated_by?: string; updated_at?: string;
  /** A people directory that is not the IdP people sign in with on this team install (cremore.onboarding.sign_in). */
  sign_in_problem?: string;
};
export const isScheduleField = (field: FieldSpec) => field.name === "schedule_minutes" || field.schedule === true;
/** AWS vault fields that mean something only with the value-reader role on; the server ignores them otherwise. */
export const idleReaderField = (provider: string, purpose: Purpose, name: string, plan: Values) =>
  provider === "aws" && purpose === "vault" && ["value_reader_role", "secret_arns", "kms_key_arns"].includes(name)
  && plan.value_reader !== true;

export function enabledPurposes(c: Pick<ProviderConnection, "plans" | "feature_enabled">): Purpose[] {
  return PURPOSE_ORDER.filter(p => c.plans[p] && c.feature_enabled?.[p] !== false);
}
export type Created = { kind: string; id: string; purpose: Purpose; name?: string | null; collector_token?: string };
/** The public part of a credential CreMore made (a Microsoft app certificate), kept as target.generated. */
/** ``previous``: the one made before, still registered at the provider until an admin removes it there. */
export type Previous = { kid?: string; thumbprint?: string };
export type Generated = { certificate: string; thumbprint: string; sha256: string; not_before: string; not_after: string; previous?: Previous };
/** How the worker's last renewal went (cremore.onboarding.renewal): a certificate CreMore made, a GitLab token's
 * rotation, or reading the token's expiry. */
export type Renewed = { state: "OK" | "FAILED" | "RUNNING"; action?: "renew" | "retire" | "inspect"; code?: string | null; at?: string; renewed_at?: string };

export function generatedOf(c: Pick<ProviderConnection, "target"> | null | undefined): Generated | null {
  const value = c?.target.generated as Generated | undefined;
  return value && typeof value.certificate === "string" && typeof value.thumbprint === "string" ? value : null;
}

/** A signing key CreMore made (an Okta service app's): only its public JWK is ever shown. */
export type MadeKey = { public_jwk: Record<string, string>; kid: string; created_at: string; previous?: Previous };

export function madeKeyOf(c: Pick<ProviderConnection, "target"> | null | undefined): MadeKey | null {
  const value = c?.target.generated as MadeKey | undefined;
  return value && typeof value.kid === "string" && value.public_jwk && typeof value.public_jwk === "object" ? value : null;
}

export type HealthItem = {
  key: string; kind: string; id: string; provider: string; name: string;
  auth_state: "READY" | "EXPIRING" | "REAUTH_REQUIRED" | "PERMISSION_LIMITED" | "SECRET_UNAVAILABLE" | "DISABLED" | "UNKNOWN";
  auth_reason: string | null; auth_renewal?: string; expires_at: string | null; expires_source?: "PROVIDER" | "OPERATOR" | null;
  expiry_stage: string;
  last_success_at: string | null; last_failure_at: string | null; last_failure_code: string | null;
  last_status: "FAILED" | "NOT_COLLECTED" | "PARTIAL" | "COMPLETE"; freshness: string;
};
export type Health = { items: HealthItem[] };
export const HEALTH_PATH = "operations/connections";
/** Services the company IdP already lists (its app names) that no connection covers yet. */
export const SUGGESTIONS_PATH = "provider-connections/suggestions";
export type Suggestion = { provider: string; apps: string[]; count: number };

/** What a suggestion says about where it came from: the app names the IdP lists, a few of them. */
export function suggestionText(item: Suggestion, L: Say): string {
  const more = item.count - item.apps.length;
  return L(`회사 IdP의 앱: ${item.apps.join(", ")}${more > 0 ? ` 외 ${more}개` : ""}`, `Company IdP apps: ${item.apps.join(", ")}${more > 0 ? ` and ${more} more` : ""}`);
}

/* ---------- catalog rules ---------- */

/** Whether a field or permission with ``when: {target field: [values]}`` applies (catalog.applies); ``"*"``
 * among the values stands for any value that is set. */
export function applies(item: { when?: Record<string, string[]> }, target: Record<string, unknown>) {
  return Object.entries(item.when ?? {}).every(([name, values]) => {
    const value = target[name];
    const set = value !== undefined && value !== null && value !== "" && !(Array.isArray(value) && !value.length);
    return values.includes(String(value ?? "")) || (values.includes("*") && set);
  });
}

const forEdition = (item: { editions?: string[] }, edition: string) => !item.editions?.length || item.editions.includes(edition);

/** Whether ``m`` serves ``p`` in ``edition``: one of its purposes, and within its ``purpose_editions`` there. */
export const serves = (m: Method, p: Purpose, edition: string) =>
  m.purposes.includes(p) && (m.purpose_editions?.[p] ?? [edition]).includes(edition);

/** The auth methods that serve every one of ``purposes`` in ``edition``, recommended first (catalog.methods_for). */
export function methodsFor(d: Descriptor, purposes: Purpose[], edition: string, retainedMethod?: string): Method[] {
  if (purposes.some(p => !d.purposes[p] || (d.purposes[p]?.editions?.length && !d.purposes[p]!.editions!.includes(edition)))) return [];
  return d.auth_methods.filter(method => (method.new_setup !== false || method.id === retainedMethod)
    && (method.purposes.some(p => d.purposes[p] && forEdition(d.purposes[p]!, edition)) || !purposes.length && method.authentication_only)
    && purposes.every(p => serves(method, p, edition)) && forEdition(method, edition))
    .sort((a, b) => Number(Boolean(a.authentication_only)) - Number(Boolean(b.authentication_only)));
}

/** Whether the plan's choices leave a permission unneeded: its ``option`` is off, or its ``unless`` is on. */
const optedOut = (p: Permission, plan: Values) => Boolean((p.option && plan[p.option] !== true) || (p.unless && plan[p.unless] === true)
  || (p.nonempty && (!plan[p.nonempty] || !plan[p.nonempty].toString().trim())));

/** The checklist a purpose shows for a method and target (catalog.permissions_for), and for the plan's choices when
 * they are known. */
export function permissionsFor(d: Descriptor, purpose: Purpose, method: string, target: Record<string, unknown>, plan?: Values): Permission[] {
  if (plan) plan = permissionPlan(d, purpose, plan);
  return (d.purposes[purpose]?.permissions ?? []).filter(p => (!p.methods?.length || p.methods.includes(method)) && applies(p, target)
    && (!plan || !optedOut(p, plan)));
}

export function purposesOf(d: Descriptor): Purpose[] {
  return PURPOSE_ORDER.filter(p => d.purposes[p]);
}

function permissionPlan(d: Descriptor, purpose: Purpose, plan: Values): Values {
  return d.provider === "github" && purpose === "inventory"
    ? { ...plan, enterprise_audit: plan.enterprise_audit === true || plan.token_digests === true } : plan;
}

/** Display eligibility only; the provider check still proves permission and entitlement. */
export function purposesForEdition(d: Descriptor, edition: string): Purpose[] {
  return purposesOf(d).filter(p => methodsFor(d, [p], edition).length > 0);
}

export type CollectionEntry = "account" | "exposure";
/** Separate new inventory connections from content scans without rewriting existing owners. */
export function forCollectionEntry(d: Descriptor, entry: CollectionEntry): Descriptor {
  const purposes = Object.fromEntries(Object.entries(d.purposes).filter(([p]) => entry === "exposure" ? p === "exposure" : p !== "exposure"));
  return { ...d, purposes, auth_methods: d.auth_methods.map(method => ({ ...method,
    authentication_only: entry === "account" && Boolean(method.auth_first) && method.purposes.includes("exposure")
      && !method.purposes.some(p => purposes[p]),
  })) };
}

/** Whether a purpose belongs to a card's entry: content scans to "exposure", every other feature to "account". */
export const inEntryView = (p: Purpose, entry?: CollectionEntry) => !entry || (p === "exposure") === (entry === "exposure");
/** The content-scan card's own name and mark: AWS scans Amazon S3; another service reads as its content scan. */
export function scanEntryOf(d: Descriptor, L: Say): { title: string; logo: string } {
  return d.provider === "aws" ? { title: "Amazon S3", logo: "s3" } : { title: `${label(d, L)} · ${L("콘텐츠 검사", "Content scan")}`, logo: d.provider };
}

/** Whether ``purpose`` can join ``chosen`` in one connection: some method must serve them all. */
export function combinable(d: Descriptor, chosen: Purpose[], purpose: Purpose, edition: string, retainedMethod?: string) {
  const all = Array.from(new Set([...chosen, purpose]));
  // The credential that disables or revokes is its own connection (service.create): no scan or collection uses it.
  if (all.includes("remediation") && all.length > 1) return false;
  return methodsFor(d, all, edition, retainedMethod).length > 0;
}

export type Values = Record<string, string | boolean | string[]>;

function defaultOf(field: FieldSpec): string | boolean | string[] {
  const kind = field.kind ?? "text";
  if (kind === "bool") return field.default === true;
  if (kind === "choices") return Array.isArray(field.default) ? field.default.map(String) : [];
  if (field.default === undefined || field.default === null) return "";
  return Array.isArray(field.default) ? field.default.join(", ") : String(field.default);
}

export function defaults(fields: FieldSpec[]): Values {
  return Object.fromEntries(fields.map(field => [field.name, defaultOf(field)]));
}

/** Stored target or plan values as the form holds them. */
export function valuesOf(fields: FieldSpec[], stored: Record<string, unknown>): Values {
  const out = defaults(fields);
  for (const field of fields) {
    const value = stored[field.name];
    if (value === undefined || value === null) continue;
    if (field.kind === "bool") out[field.name] = value === true;
    else if (field.kind === "choices") out[field.name] = Array.isArray(value) ? value.map(String) : [];
    else out[field.name] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return out;
}

/** Target fields that apply: the edition's, and a ``when`` field only when the fields before it say so
 * (service._fields evaluates ``when`` against the plain fields with their defaults). */
export function targetFields(d: Descriptor, edition: string, values: Values): FieldSpec[] {
  const wanted = (d.target ?? []).filter(field => forEdition(field, edition));
  const plain = Object.fromEntries(wanted.filter(field => !field.when).map(field => [field.name, values[field.name] ?? defaultOf(field)]));
  return wanted.filter(field => !field.when || applies(field, plain));
}

/** Edition defaults initialize new plans (service._fields). A saved plan missing a later option keeps its base default. */
export function planFields(d: Descriptor, purpose: Purpose, edition: string, target: Record<string, unknown>, saved = false): FieldSpec[] {
  return (d.purposes[purpose]?.plan ?? []).filter(field => forEdition(field, edition) && applies(field, target))
    .map(field => field.target_default && field.target_default in target ? { ...field, default: target[field.target_default] }
      : !saved && field.edition_defaults && edition in field.edition_defaults ? { ...field, default: field.edition_defaults[edition] } : field);
}

/** One inventory type for a target: collected always (no field), or while its plan option is on. */
export type TypeChoice = { type: InventoryType; field?: FieldSpec; option?: string; on: boolean };

/** The types an inventory lists for this edition and target, each with how it is turned on. The first
 * binding that applies decides; a type with bindings and none that applies is not listed here. */
export function typeChoices(d: Descriptor, edition: string, target: Record<string, unknown>, fields: FieldSpec[], values: Values): TypeChoice[] {
  const out: TypeChoice[] = [];
  for (const type of d.purposes.inventory?.types ?? []) {
    if (!forEdition(type, edition) || !applies(type, target)) continue;
    if (!type.plan?.length) { out.push({ type, on: true }); continue; }
    const binding = type.plan.find(item => item.always ? forEdition(item, edition) && applies(item, target) : fields.some(field => field.name === item.field));
    if (!binding) continue;
    const field = binding.always ? undefined : fields.find(item => item.name === binding.field);
    if (!field) { out.push({ type, on: true }); continue; }
    const value = values[field.name];
    const on = binding.option ? Array.isArray(value) && value.includes(binding.option)
      : field.kind === "bool" ? value === true : Array.isArray(value) ? value.length > 0 : typeof value === "string" && Boolean(value.trim());
    out.push({ type, field, option: binding.option, on });
  }
  return out;
}

/** Whether a type's checkbox switches it: a bool option or a choices option does; a list names what to read. */
export const switchable = (choice: TypeChoice) => Boolean(choice.field && (choice.option || choice.field.kind === "bool"));

/** Plan values with a switchable type turned on or off. */
export function switchType(choice: TypeChoice, values: Values, on: boolean): Values {
  const field = choice.field;
  if (!field || !switchable(choice)) return values;
  if (choice.option) {
    const list = Array.isArray(values[field.name]) ? values[field.name] as string[] : [];
    return { ...values, [field.name]: on ? Array.from(new Set([...list, choice.option])) : list.filter(item => item !== choice.option) };
  }
  return { ...values, [field.name]: on };
}

/** Plan fields the type list already shows: a bool that turns a type on, a choices field whose every option does. */
export function typeFields(choices: TypeChoice[], fields: FieldSpec[]): Set<string> {
  const out = new Set<string>();
  for (const field of fields) {
    const bound = choices.filter(choice => choice.field?.name === field.name && switchable(choice));
    if (field.kind === "bool" && bound.length) out.add(field.name);
    if (field.kind === "choices" && bound.length && (field.options ?? []).every(option => bound.some(choice => choice.option === option.id))) out.add(field.name);
  }
  return out;
}

/** What an exposure scan reads for an edition and target (a location may need a target field, such as a
 * Microsoft connection's Azure DevOps project). */
export function scansFor(d: Descriptor, edition: string, target: Record<string, unknown> = {}): ScanItem[] {
  return (d.purposes.exposure?.scans ?? []).filter(item => forEdition(item, edition) && (!item.when || applies(item, target)));
}

const split = (text: string) => text.split(/[\s,]+/).map(part => part.trim()).filter(Boolean);

/** A list field's value as stored (an array) or as the form holds it (comma-separated text). */
export function listValue(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : typeof value === "string" ? split(value) : [];
}

/** Form values as the API takes them: empty fields left out, lists split, numbers as integers. */
export function payload(fields: FieldSpec[], values: Values): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    const value = values[field.name];
    const kind = field.kind ?? "text";
    if (kind === "bool") { if (typeof value === "boolean") out[field.name] = value; continue; }
    if (kind === "choices") { if (Array.isArray(value)) out[field.name] = value; continue; }
    if (typeof value !== "string" || !value.trim()) continue;
    if (kind === "list") out[field.name] = split(value);
    else if (kind === "number") { const n = Number(value); out[field.name] = Number.isInteger(n) ? n : value; }
    else if (kind === "multiline") out[field.name] = value;
    else out[field.name] = value.trim();
  }
  return out;
}

/** The first required field left empty, for a step's Next button. */
export function missingRequired(fields: FieldSpec[], values: Values): FieldSpec | undefined {
  return fields.find(field => field.required && (() => {
    const value = values[field.name];
    return Array.isArray(value) ? !value.length : typeof value === "string" ? !value.trim() : false;
  })());
}

/** A stored target or plan value as text. */
export function shown(field: FieldSpec | undefined, value: unknown, L: Say): string {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value === "boolean") return value ? L("사용", "On") : L("사용 안 함", "Off");
  if (Array.isArray(value)) {
    const names = value.map(item => field?.options?.find(option => option.id === item)).map((option, index) => option ? L(option.label_ko, option.label) : String(value[index]));
    return names.join(", ");
  }
  const option = field?.options?.find(item => item.id === value);
  return option ? L(option.label_ko, option.label) : String(value);
}

export const label = (item: { label: string; label_ko: string }, L: Say) => L(item.label_ko, item.label);

/** What the connection points at, in a few words: "acme", "123456789012 +1". */
export function targetSummary(d: Descriptor | undefined, c: Pick<ProviderConnection, "target" | "name">): string {
  if (c.target.version === 2 && Array.isArray(c.target.roots)) {
    return c.target.roots.map((r: { target: Record<string, unknown> }) => targetSummary(d, { name: c.name, target: r.target })).join(", ");
  }
  for (const field of d?.target ?? []) {
    const value = c.target[field.name];
    if (typeof value === "string" && value && field.kind !== "choice" && field.kind !== "multiline") return value;
    if (Array.isArray(value) && value.length) return value.length > 1 ? `${value[0]} +${value.length - 1}` : String(value[0]);
  }
  return c.name;
}

/** Shared field conditions for displaying options; every root is checked on the server. */
export function sharedTarget(target: Record<string, unknown>): Record<string, unknown> {
  if (target.version !== 2 || !Array.isArray(target.roots) || !target.roots.length) return target;
  const roots = target.roots as { target: Record<string, unknown> }[];
  return Object.fromEntries(Object.entries(roots[0].target).filter(([key, value]) =>
    roots.every(root => JSON.stringify(root.target[key]) === JSON.stringify(value))));
}

/** A row's second line: a name the operator gave, or for a default name ("GitLab · group") what the
 * connection points at; nothing when that would only repeat the service. */
export function shortName(d: Descriptor | undefined, c: Pick<ProviderConnection, "name" | "target">) {
  const prefix = d ? `${d.label} · ` : "";
  if (!prefix || !c.name.startsWith(prefix)) return c.name;
  const summary = targetSummary(d, c);
  return summary === c.name ? "" : summary;
}

/* ---------- checks ---------- */

/** A check has answered for the connection as it is now. */
export function checked(c: ProviderConnection) {
  const at = Date.parse(c.checks.checked_at ?? ""), asked = Date.parse(c.checks.requested_at ?? "");
  return Boolean(c.checks.checked_at) && !c.checks.stale && (Number.isNaN(asked) || at >= asked);
}

/** A connection's check answers; with its descriptor, without those for an option that is off (``plans``: the
 * choices being made, else the saved ones or their defaults). */
export function checkItems(c: ProviderConnection, purposes: Purpose[] = c.purposes, d?: Descriptor,
  plans?: Partial<Record<Purpose, Values>>): CheckItem[] {
  return purposes.flatMap(p => {
    const items = c.checks.results[p]?.items ?? [];
    if (!d) return items;
    const plan = permissionPlan(d, p, plans?.[p] ?? valuesOf(planFields(d, p, c.edition, c.target ?? {}, p in (c.plans ?? {})), c.plans?.[p] ?? {}));
    // One permission can be declared under several options (or methods): it is hidden only when none of the entries
    // for this connection's method and target needs it, as permissionsFor picks them.
    const declared = (d.purposes[p]?.permissions ?? []).filter(item => (!item.methods?.length || item.methods.includes(c.auth_method))
      && applies(item, c.target ?? {}));
    const needed = new Set(declared.filter(item => item.required !== false && !optedOut(item, plan)).map(item => item.id));
    const off = new Set(declared.map(item => item.id).filter(id => !needed.has(id)));
    return items.filter(item => !off.has(item.permission));
  });
}

export function checkSummary(items: CheckItem[]): "ok" | "missing" | "error" | "unreported" | "none" {
  if (!items.length) return "none";
  if (items.some(item => item.status === "MISSING")) return "missing";
  if (items.some(item => item.status === "ERROR")) return "error";
  if (items.some(item => item.status === "NOT_REPORTED")) return "unreported";
  return "ok";
}

const DETAILS: Record<string, [string, string]> = {
  HTTP_401: ["인증이 만료되었거나 거절되었습니다. 다시 인증하세요.", "Authentication expired or was rejected. Sign in again."],
  HTTP_403: ["이 조회가 거절되었습니다. 표시된 작업의 권한·리소스 공유·조직 정책을 확인하세요.", "This read was denied. Check access for the named operation, resource sharing and organization policy."],
  HTTP_429: ["공급자 호출 한도에 도달했습니다. 잠시 뒤 다시 확인하세요.", "The provider rate limit was reached. Try again shortly."],
  NOT_CHECKED: ["확인하지 않음", "Not checked"],
  CUSTOMER_CLI_REPORTS_ON_UPLOAD: ["CLI가 업로드할 때 확인", "Reported when the CLI uploads"],
  LOGIN_REQUIRED: ["로그인 필요", "Sign-in required"],
  TARGET_NOT_VISIBLE: ["대상이 보이지 않음", "Target not visible"],
  INSTALLED_ON_ANOTHER_ACCOUNT: ["다른 계정에 설치됨", "Installed on another account"],
  WORKSPACE_ID_REQUIRED: ["워크스페이스 ID 필요", "Workspace ID required"],
  STORAGE_ACCOUNT_REQUIRED: ["스토리지 계정 필요", "Storage account required"],
  SCANNER_ACCESS_REQUIRED: ["계정 접근이 막혀 이 권한은 아직 확인하지 못했습니다.", "Account access failed, so this permission has not been checked yet."],
  IAM_POLICY_COLLECTION_DISABLED: ["설치 설정 IAM_POTENTIAL_ACCESS_MODE=disabled가 IAM 정책 조회를 차단하고 있습니다.", "The installation setting IAM_POTENTIAL_ACCESS_MODE=disabled blocks IAM policy reads."],
  IAM_POLICY_READ_DENIED: ["IAM 사용자·그룹 정책 읽기가 거절됐습니다. 수집 역할의 GetUser·List/GetUserPolicy·List/GetGroupPolicy·GetPolicy·GetPolicyVersion 권한을 확인하세요.", "IAM user/group policy reads were denied. Check the collection role's GetUser, user/group policy list/read, GetPolicy and GetPolicyVersion permissions."],
  IAM_POLICY_READ_FAILED: ["IAM 정책 읽기를 확인하지 못했습니다. 연결 상태를 확인한 뒤 다시 시도하세요.", "IAM policy reads could not be verified. Check the connection and retry."],
  IAM_POLICY_NO_USER_TO_CHECK: ["정책 읽기를 점검할 IAM 사용자가 없습니다. IAM 정책 메타데이터 수집을 끄고 진행한 뒤 사용자를 등록하면 다시 켤 수 있습니다.", "No IAM user is available to verify policy reads. Turn off IAM policy metadata collection for now and enable it after adding a user."],
  IAM_POLICY_CHECK_LIMIT: ["정책 권한 점검의 호출 한도에 도달했습니다. 수집 역할과 정책 구성을 확인하세요.", "The policy preflight reached its request limit. Review the collection role and policy configuration."],
  ASSUME_ROLE_DENIED: ["서버가 수집 역할을 맡지 못했습니다. 수집 역할의 신뢰 대상·ExternalId와 서버의 sts:AssumeRole 권한을 아래 역할 설정값과 비교하세요.", "The server could not assume the collection role. Compare its trusted principal and ExternalId, and the server's sts:AssumeRole permission, with the role setup below."],
  NO_USER_TO_ASK_ABOUT: ["확인할 사용자 없음", "No user to ask about"],
  NO_SUBSCRIPTION_CHOSEN: ["구독을 지정하지 않음", "No subscription chosen"],
  NO_REPOSITORY_TO_READ: ["읽을 저장소 없음", "No repository to read"],
  NO_PAGE_SHARED_WITH_INTEGRATION: ["연결에 공유된 페이지 없음", "No page shared with the connection"],
  NOT_AN_ADMINISTRATOR: ["관리자 계정이 아님(GitLab Admin Mode가 켜져 있으면 admin_mode 범위도 필요)", "Not an administrator (with GitLab Admin Mode on, the admin_mode scope too)"],
  ACCESS_LEVEL_TOO_LOW: ["필요한 역할보다 낮은 권한", "Below the role it needs"],
  ROOT_TOKEN_NOT_RECOMMENDED: ["루트 권한 토큰 · 읽기 전용 정책의 토큰을 권장", "Root token · a read-only policy's token is recommended"],
  NOT_AN_OWNER: ["소유자 계정이 아님", "Not an owner"],
  SLACK_SCOPE_MISSING: ["토큰에 이 범위가 없음", "The token lacks this scope"],
  SLACK_TEAMS_READ_REQUIRED: ["워크스페이스를 하나씩 고르려면 조직에 설치한 관리자 앱에 admin.teams:read 권한이 필요합니다. 없으면 조직 전체를 대상으로 고르세요.", "Picking a single workspace requires admin.teams:read on the organization-installed admin app. Without it, pick the whole organization."],
  SLACK_WORKSPACES_NOT_CONFIRMED: ["워크스페이스 소속을 확인하지 못했습니다. 권한을 확인한 뒤 다시 조회하세요.", "Workspace membership could not be confirmed. Check access and retry."],
  SLACK_ENTERPRISE_REQUIRED: ["Enterprise Grid 조직이 필요함", "An Enterprise Grid organization is required"],
  SLACK_TOKEN_REJECTED: ["Slack이 토큰을 거부함", "Slack rejected the token"],
  SLACK_ANOTHER_ORGANIZATION: ["다른 조직의 토큰", "A token of another organization"],
  SLACK_ADMIN_USER_TOKEN_REQUIRED: ["관리자 사용자 토큰이 필요함", "An admin user token is required"],
  SLACK_APP_NOT_INSTALLED_ON_ORGANIZATION: ["앱을 조직에 설치해야 함", "Install the app on the organization"],
  RATE_LIMITED: ["요청 한도에 걸림 · 잠시 뒤 다시 확인", "Rate limited · check again shortly"],
  KEY_VAULT_REQUIRED: ["Key Vault 필요", "Key Vault required"],
  INSTALLATION_UNREADABLE: ["설치 정보를 읽지 못함", "Installation unreadable"],
  GITHUB_APP_READ_ONLY_REFUSED: ["GitHub가 읽기 전용 토큰을 거절함 · App 권한 확인", "GitHub refused a read-only token · check the App's permissions"],
  GITHUB_APP_TOKEN_NOT_READ_ONLY: ["읽기 전용이 아닌 토큰이 와서 쓰지 않음", "A token that was not read-only came back and was not used"],
  GITHUB_APP_REJECTED: ["GitHub가 App이나 그 설치를 거절함", "GitHub refused the App or its installation"],
  GITHUB_TOKEN_REJECTED: ["토큰이 거절됨", "Token rejected"],
  CLASSIC_TOKEN_REQUIRED: ["클래식 토큰 필요", "Classic token required"],
  ADMIN_EVENTS_OFF: ["관리 이벤트를 켜지 않음", "Admin events are off"],
  ACCESS_LEVEL_BELOW_MAINTAINER: ["Maintainer보다 낮은 권한", "Below Maintainer"],
  ACCESS_DENIED: ["접근 거부", "Access denied"],
  CREDENTIAL_UNAVAILABLE: ["자격증명을 읽지 못함", "Credential unavailable"],
  SECRET_RESOLVER_UNAVAILABLE: ["비밀 저장소를 쓸 수 없음", "Secret store unavailable"],
  REQUEST_FAILED: ["요청 실패", "Request failed"],
  CATALOG_REFRESH_TIMEOUT: ["목록을 가져오는 작업이 끝나지 않음", "Reading the list did not finish"],
  SCOPE_CATALOG_NOT_COLLECTED: ["목록을 아직 가져오지 못함", "The list is not read yet"],
  CONNECTION_PAUSED: ["연동이 중지됨", "The integration is stopped"],
  SCOPE_CATALOG_CHANGED: ["목록이 바뀜", "The list changed"],
  SCOPE_VERSION_CONFLICT: ["다른 사람이 먼저 바꿈", "Someone changed it first"],
  UNREACHABLE: ["서버에 연결하지 못함", "Could not reach the server"],
  NO_STORAGE_ACCOUNT_CHOSEN: ["스토리지 계정을 정하지 않음", "No storage account chosen"],
  AZURE_CERTIFICATE_NOT_REGISTERED: ["앱 등록에 이 인증서가 없음", "The app registration does not hold this certificate"],
  AZURE_APPLICATION_NOT_FOUND: ["이 테넌트에 그 앱 등록이 없음", "No such app registration in this tenant"],
  AZURE_TENANT_NOT_FOUND: ["테넌트를 찾지 못함", "Tenant not found"],
  AZURE_APPLICATION_DISABLED: ["앱이 사용 중지됨", "The app is disabled"],
  AZURE_SERVICE_PRINCIPAL_MISSING: ["앱의 서비스 주체가 없음", "The app has no service principal"],
  AZURE_RESOURCE_NOT_IN_TENANT: ["이 테넌트에 없는 서비스", "The service is not in this tenant"],
  AZURE_CLOCK_SKEW: ["CreMore 서버 시계가 맞지 않음", "CreMore's server clock is off"],
  AZURE_ENTRA_PREMIUM_REQUIRED: ["테넌트에 Microsoft Entra ID P1 또는 P2가 없어 Graph로 로그인 로그를 읽을 수 없음 · 라이선스를 더하거나 이 옵션을 끔",
    "The tenant has no Microsoft Entra ID P1 or P2, which Graph needs for sign-in logs · add the license or turn this option off"],
  AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND: ["테넌트 루트 관리 그룹이 아직 없음 · Azure Portal의 관리 그룹 화면에서 관리 그룹 사용을 시작하면 만들어지며, 쓰지 않으면 Azure 역할 옵션을 끔",
    "The tenant has no root management group yet · starting to use management groups on the Azure portal's Management groups page makes it; otherwise turn the Azure roles option off"],
  AZURE_TOKEN_REFUSED: ["Microsoft가 로그인을 거절함", "Microsoft refused the sign-in"],
  AZURE_TOKEN_UNAVAILABLE: ["Microsoft 로그인이 응답하지 않음 · 잠시 뒤 다시 확인", "Microsoft sign-in did not answer · check again shortly"],
  AZURE_CERTIFICATE_INVALID: ["저장한 인증서를 읽지 못함", "The stored certificate could not be read"],
  TOKEN_RENEWED_BY_HAND: ["없으면 만료 전에 직접 새 토큰을 넣어야 함", "Without it the token is replaced by hand before it expires"],
  OKTA_TOKEN_REFUSED: ["Okta가 로그인을 거절함 · 서비스 앱의 공개 키·클라이언트 ID·권한 확인", "Okta refused the sign-in · check the service app's public key, client ID and grants"],
  OKTA_TOKEN_UNAVAILABLE: ["Okta 로그인이 응답하지 않음 · 잠시 뒤 다시 확인", "Okta sign-in did not answer · check again shortly"],
  OKTA_ACCESS_DENIED: ["Okta가 읽기를 거절함 · 사용자는 okta.users.read, 앱 목록은 okta.apps.read와 관리자 역할 확인", "Okta refused the read · check okta.users.read for the users, okta.apps.read for the app list, and the admin role"],
  KEYCLOAK_VIEW_CLIENTS_REQUIRED: ["클라이언트 목록을 볼 수 없음 · 서비스 계정에 realm-management view-clients 역할을 줌", "The client list is not visible · give the service account the realm-management view-clients role"],
  GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED: ["최고 관리자가 관리 콘솔 > 보안 > 액세스 및 데이터 관리 > API 제어 > 도메인 전체 위임 관리에서 이 클라이언트 ID에 https://www.googleapis.com/auth/admin.directory.user.readonly 범위를 허용해야 함(적용까지 최대 24시간)",
    "A super admin allows this client ID https://www.googleapis.com/auth/admin.directory.user.readonly under Admin console > Security > Access and data control > API controls > Manage Domain Wide Delegation (up to 24 hours to apply)"],
  GOOGLE_WORKSPACE_TOKEN_REFUSED: ["Google이 위임 로그인을 거절함 · 서비스 계정 키가 살아 있는지, 관리자 이메일이 맞는지 확인", "Google refused the delegated sign-in · check the service account key is active and the administrator's address"],
  GOOGLE_WORKSPACE_TOKEN_UNAVAILABLE: ["Google 로그인이 응답하지 않음 · 잠시 뒤 다시 확인", "Google sign-in did not answer · check again shortly"],
  GOOGLE_WORKSPACE_ACCESS_DENIED: ["사용자 목록을 읽을 권한이 없음 · 위임받는 계정이 최고 관리자인지 확인", "No access to the users · check the administrator acted as is a super administrator"],
  GOOGLE_WORKSPACE_ADMIN_INVALID: ["위임받을 관리자 이메일이 맞지 않음", "The administrator's address is not valid"],
  GOOGLE_WORKSPACE_ADMIN_OUTSIDE_DOMAIN: ["위임받을 관리자가 연결한 도메인의 주소가 아님 · 그 도메인의 관리자 주소를 입력", "The administrator is not an address in the connected domain · enter an administrator of that domain"],
  GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN: ["위임받을 계정이 최고 관리자가 아님 · 일부 조직 단위만 보는 관리자로는 누가 떠났는지 알 수 없음", "The administrator acted as is not a super administrator · one who sees only some organizational units cannot tell who left"],
  GOOGLE_WORKSPACE_API_NOT_ENABLED: ["서비스 계정의 Google Cloud 프로젝트에서 Admin SDK API를 사용 설정해야 함", "Turn on the Admin SDK API in the service account's Google Cloud project"],
  GOOGLE_WORKSPACE_RATE_LIMITED: ["Google 요청 한도에 걸림 · 잠시 뒤 다시 확인", "Google's request limit was reached · check again shortly"],
  GOOGLE_WORKSPACE_UNAVAILABLE: ["Google이 응답하지 않음 · 잠시 뒤 다시 확인", "Google did not answer · check again shortly"],
  GOOGLE_WORKSPACE_KEY_INVALID: ["저장한 서비스 계정 키를 읽지 못함", "The stored service account key could not be read"],
  ATLASSIAN_OAUTH_TOKEN_REFUSED: ["Atlassian이 클라이언트를 거절함 · 클라이언트 ID·시크릿 확인", "Atlassian refused the client · check the client ID and secret"],
  ATLASSIAN_OAUTH_UNAVAILABLE: ["Atlassian 로그인이 응답하지 않음 · 잠시 뒤 다시 확인", "Atlassian sign-in did not answer · check again shortly"],
  CONFLUENCE_GATEWAY_ADDRESS_INVALID: ["게이트웨이 주소는 https://api.atlassian.com/ex/confluence/<Cloud ID>/wiki 형식이어야 함", "A gateway address is https://api.atlassian.com/ex/confluence/<cloud ID>/wiki"],
  TARGET_INCOMPLETE: ["연동 대상 정보가 빠짐", "The target is incomplete"],
  VALUE_READ_PERMISSION_NOT_CHECKED: ["현재 사전 점검으로 값 읽기 권한을 확인할 수 없습니다. 값 읽기가 필요한 기능·옵션을 제외하고 다시 확인하세요.", "The preflight check cannot currently verify permission to read values. Remove the features or options that require values and check again."],
  AWS_SCANNER_ROLE_DENIES_SECRET_VALUES: ["CreMore의 CloudFormation 템플릿은 수집 역할의 Secrets Manager 값 읽기(GetSecretValue)를 명시적으로 거부하며, 허용을 더해도 바뀌지 않습니다. 금고 대조를 빼고 다시 확인하세요.",
    "CreMore's CloudFormation template explicitly denies the collection role Secrets Manager value reads (GetSecretValue), and no added Allow changes that. Leave out the vault comparison and check again."],
  AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES: ["CreMore의 CloudFormation 템플릿은 수집 역할에 Parameter Store 값 읽기(GetParametersByPath)를 주지 않고, 사전 점검은 값을 읽어 권한을 확인하지 않습니다. 경로를 비우고 다시 확인하세요.",
    "CreMore's CloudFormation template gives the collection role no Parameter Store value reads (GetParametersByPath), and the preflight check does not read values to confirm access. Clear the paths and check again."],
  EXPOSURE_SCHEDULES_DISABLED: ["예약 검사 전체 스위치가 꺼져 있습니다. 실행 설정에서 켜거나 수동 수집을 선택하세요.", "The scan schedule switch is off. Enable it in collection settings or choose manual collection."],
  TARGET_OWNER_NOT_CHECKED: ["조직·엔터프라이즈 소유자 권한을 확인하지 못했습니다. 토큰 권한과 대상 접근을 확인하고 다시 시도하세요.", "Organization or enterprise ownership could not be verified. Check the token permissions and target access, then retry."],
  CONFLUENCE_CLOUD_ID_UNAVAILABLE: ["사이트의 Cloud ID를 읽지 못함 · 주소 확인", "The site's cloud ID could not be read · check the address"],
  CONFLUENCE_SPACE_NOT_VISIBLE: ["공간이 없거나 서비스 계정에 보기 권한이 없음", "No such space, or the service account cannot view it"],
  CONFLUENCE_NO_PAGE_TO_TRY: ["공간에 확인할 페이지가 없음", "No page in the space to try"],
  GITHUB_IDENTITY_SAML_NOT_ENABLED: ["GitHub이 이 조직의 SAML 신원 공급자를 보여 주지 않음 · 조직에 SAML SSO를 설정했는지 확인하고, 엔터프라이즈에 SAML·OIDC를 설정했다면 엔터프라이즈 소유자의 classic PAT로 엔터프라이즈 신원을 읽음",
    "GitHub shows no SAML identity provider for this organization · check that SAML SSO is set on the organization; with SAML or OIDC set on the enterprise, read the enterprise's identities with an enterprise owner's classic PAT"],
};

export function detailText(code: string | undefined, L: Say): string {
  if (!code) return "";
  const known = DETAILS[code] ?? CODES[code];
  if (known) return L(known[0], known[1]);
  const http = /^HTTP_(\d{3})$/.exec(code);
  return http ? `HTTP ${http[1]}` : code;
}

/* ---------- how a connection is doing ---------- */

export type Tone = "ok" | "warn" | "partial" | "running" | "setup" | "off";
export type RowState = { tone: Tone; label: string; note?: string; fix?: "resume" | "reauth" | "credential" | "recheck" | "logs" };

/** An owned record's key in operations/connections (health, and an operator-entered expiry). */
export function healthKey(child: { kind: string; id: string }): string {
  return child.kind === "content" ? `content:${child.id}` : child.kind === "aws_account" ? `aws_account:${child.id}` : `coverage:${child.id}`;
}

/** The health items of a connection's owned records (operations/connections keys). */
export function healthOf(c: ProviderConnection, health: HealthItem[] | undefined): HealthItem[] {
  if (!health) return [];
  const keys = new Set(c.children.filter(child => c.feature_enabled?.[child.purpose] !== false).map(healthKey));
  return health.filter(item => keys.has(item.key));
}

/** Services of one vendor that are connected one after another (Atlassian's Confluence, Bitbucket and organization). */
const FAMILIES: Record<string, string[]> = { Atlassian: ["confluence", "bitbucket", "atlassian"] };

/** The vendor a service belongs to and its other services, or null. */
export function familyOf(provider: string): { name: string; others: string[] } | null {
  const found = Object.entries(FAMILIES).find(([, members]) => members.includes(provider));
  return found ? { name: found[0], others: found[1].filter(item => item !== provider) } : null;
}

/** Whether a method holds a token an admin replaces before it expires (a secret field), so its date can be entered. */
export function takesExpiry(method: Method): boolean {
  return method.renewal === "EXPIRES" && (method.fields ?? []).some(field => field.secret);
}

/** The end of the chosen day in the viewer's time zone, as the operations API takes it (as the Operations page
 * enters it), and that day again. */
export function expiryAt(day: string): string | null {
  const end = new Date(`${day}T23:59:59`);
  return day && !Number.isNaN(end.getTime()) ? end.toISOString() : null;
}
export function expiryDay(at: string | null | undefined): string {
  const when = at ? new Date(at) : null;
  if (!when || Number.isNaN(when.getTime())) return "";
  return `${when.getFullYear()}-${String(when.getMonth() + 1).padStart(2, "0")}-${String(when.getDate()).padStart(2, "0")}`;
}

/** The owned records an entered day (or ``""`` to clear) changes: listed in health, collecting, neither renewing
 * themselves nor dated by their provider, and not already on that day; clearing touches only an entered date. */
export function expiryKeys(c: ProviderConnection, health: HealthItem[], day: string): string[] {
  return healthOf(c, health).filter(item => item.auth_state !== "DISABLED" && item.auth_renewal !== "AUTO"
    && item.expires_source !== "PROVIDER"
    && (day ? !(item.expires_source === "OPERATOR" && expiryDay(item.expires_at) === day) : item.expires_source === "OPERATOR"))
    .map(item => item.key);
}

/** Saves the entered day (``""`` clears it) on each record; the keys that could not be saved. */
export async function saveExpiry(put: (key: string, body: { expires_at: string | null }) => Promise<unknown>,
  keys: string[], day: string): Promise<string[]> {
  const body = { expires_at: day ? expiryAt(day) : null };
  const results = await Promise.allSettled(keys.map(key => put(key, body)));
  return keys.filter((_key, index) => results[index].status === "rejected");
}

/** One warning per connection whose token is about to expire (each record it serves carries the date); a record
 * no connection owns is its own. */
export function expiringConnections(items: HealthItem[], connections: ProviderConnection[]): { key: string; name: string; expires_at: string }[] {
  const owner = new Map<string, ProviderConnection>();
  for (const c of connections) for (const child of c.children) owner.set(healthKey(child), c);
  const out = new Map<string, { key: string; name: string; expires_at: string }>();
  for (const item of items) {
    if (item.auth_state !== "EXPIRING" || !item.expires_at) continue;
    const c = owner.get(item.key);
    const key = c ? `connection:${c.id}` : item.key;
    const known = out.get(key);
    if (!known || Date.parse(item.expires_at) < Date.parse(known.expires_at)) out.set(key, { key, name: c?.name ?? item.name, expires_at: item.expires_at });
  }
  return [...out.values()];
}

export function lastRun(items: HealthItem[]): string | null {
  const times = items.map(item => item.last_success_at).filter((value): value is string => Boolean(value));
  return times.length ? times.reduce((a, b) => (Date.parse(a) >= Date.parse(b) ? a : b)) : null;
}

const FAILURES: Record<string, [string, string]> = {
  AUTH_EXPIRED: ["인증이 만료됐습니다", "The sign-in has expired"],
  AUTH_EXPIRING: ["인증 만료가 다가옵니다", "The sign-in expires soon"],
  SECRET_UNAVAILABLE: ["저장한 인증 정보를 읽지 못했습니다", "The stored credential could not be read"],
  AWS_LOGIN_REQUIRED: ["CreMore의 AWS 로그인이 필요합니다", "CreMore needs to sign in to AWS"],
  AWS_SCANNER_IDENTITY_CHANGED: ["승인한 AWS 신원과 지금 신원이 다릅니다", "The AWS identity differs from the approved one"],
};

function failureText(code: string | null, L: Say) {
  if (!code) return "";
  const known = FAILURES[code];
  return known ? L(known[0], known[1]) : code;
}

/** What the worker's certificate renewal said, for a person (cremore.onboarding.renewal codes). */
export function renewalText(code: string | null | undefined, L: Say): string {
  const known: Record<string, [string, string]> = {
    AZURE_APPLICATION_READ_REQUIRED: ["앱에 Application.Read.All이 없어 자기 앱 등록을 찾지 못했습니다", "The app lacks Application.Read.All to find its own registration"],
    AZURE_CERTIFICATE_NOT_ON_APPLICATION: ["인증서가 앱 등록이 아니라 서비스 주체에 있습니다", "The certificate is on the service principal, not the app registration"],
    AZURE_ADD_KEY_REFUSED: ["Microsoft가 새 인증서 추가를 거절했습니다(테넌트의 인증서 수명 정책, 또는 CA가 발급한 인증서만 받는 정책 · CreMore 인증서는 자체 서명)",
      "Microsoft refused the new certificate (a tenant certificate lifetime policy, or one that accepts only CA-issued certificates · CreMore's is self-signed)"],
    AZURE_REMOVE_KEY_REFUSED: ["이전 인증서를 지우지 못했습니다 · 만료되면 저절로 쓸 수 없게 됩니다", "The old certificate could not be removed · it stops working when it expires"],
    AZURE_GRAPH_UNAVAILABLE: ["Microsoft Graph가 응답하지 않았습니다 · 다음 시각에 다시 합니다", "Microsoft Graph did not answer · tried again next hour"],
    CREDENTIAL_UNAVAILABLE: ["저장한 자격증명을 읽지 못했습니다", "The stored credential could not be read"],
    GITLAB_SELF_ROTATE_SCOPE_REQUIRED: ["토큰에 self_rotate(또는 api) 범위가 없어 스스로 바꾸지 못했습니다 · 만료 전에 새 토큰을 넣으세요", "The token lacks the self_rotate (or api) scope to renew itself · enter a new token before it expires"],
    GITLAB_TOKEN_REVOKED: ["저장한 토큰이 폐기됐거나 만료됐습니다 · 새 토큰을 넣으세요", "The stored token was revoked or expired · enter a new token"],
    GITLAB_ROTATION_UNCERTAIN: ["교체 응답을 확인하지 못했습니다 · 이전 토큰이 폐기됐을 수 있어 새 토큰을 넣어야 합니다", "The rotation's answer could not be confirmed · the old token may be revoked, so enter a new one"],
    GITLAB_ROTATION_REFUSED: ["GitLab이 교체를 거절했습니다(인스턴스의 토큰 수명 정책 등) · 새 토큰을 넣으세요", "GitLab refused the rotation (an instance token lifetime policy, for one) · enter a new token"],
    GITLAB_UNAVAILABLE: ["GitLab이 응답하지 않았습니다 · 다음 시각에 다시 합니다", "GitLab did not answer · tried again next hour"],
    RENEWAL_INTERRUPTED: ["교체가 중간에 끊겼습니다 · 이전 자격증명이 폐기됐을 수 있어 새 자격증명을 넣어야 합니다", "The renewal stopped half-way · the old credential may be revoked, so enter a new one"],
  };
  if (!code) return "";
  return known[code] ? L(known[code][0], known[code][1]) : detailText(code, L);
}

type Sharing = Pick<ProviderConnection, "purposes" | "credential"> & { provider?: string; auth_method?: string };

const workerIdentity = (c: Sharing) => c.provider === "gcp" && c.auth_method === "adc";

/** One credential that both collects and acts (cremore.onboarding.service.shared_credentials): the daily collection
 * would open a credential that may revoke. Said on both integrations and with the plan; nothing is refused. The
 * worker's own Google Cloud identity (ADC) cannot be changed on the collecting side: there the acting one moves. */
export function sharedNote(c: Sharing, L: Say): string {
  const others = c.credential.shared_with ?? [];
  if (!others.length) return "";
  const shown = others.slice(0, 2).map(item => `'${item.name}'`).join(", ");
  const more = others.length - 2;
  const ko = more > 0 ? `${shown} 외 ${more}개` : shown;
  const en = more > 0 ? `${shown} and ${more} more` : shown;
  const many = others.length > 1;
  const s = many ? "s" : "";
  const verb = (plural: string, single: string) => (many ? plural : single);
  if (c.purposes.includes("remediation")) {
    return workerIdentity(c)
      ? L(`수집 연동 ${ko}도 워커 자신의 Google Cloud 신원(ADC)을 씁니다 · 조치는 Google 로그인으로 따로 두세요`,
        `Collecting integration${s} ${en} ${verb("run", "runs")} as the worker's own Google Cloud identity (ADC) too · sign actions in with Google instead`)
      : L(`수집 연동 ${ko}도 이 자격증명을 씁니다 · 조치용은 따로 두세요`,
        `Collecting integration${s} ${en} ${verb("use", "uses")} this credential too · give actions their own`);
  }
  return workerIdentity(c)
    ? L(`조치 연동 ${ko}도 워커 자신의 Google Cloud 신원(ADC)을 씁니다 · 조치 연동을 Google 로그인으로 바꾸세요`,
      `Acting integration${s} ${en} ${verb("run", "runs")} as the worker's own Google Cloud identity (ADC) too · switch ${verb("them", "it")} to Google sign-in`)
    : L(`조치 연동 ${ko}도 이 자격증명을 씁니다 · 수집용은 따로 두세요`,
      `Acting integration${s} ${en} ${verb("use", "uses")} this credential too · give collection its own`);
}

/** The integration whose credential step fixes a shared credential: this one, or for a collection that runs as the
 * worker's own Google Cloud identity, the acting one. */
export function sharedFix(c: Sharing & { id: string }): string {
  return workerIdentity(c) && !c.purposes.includes("remediation") ? c.credential.shared_with?.[0]?.id ?? c.id : c.id;
}

export function rowState(c: ProviderConnection, items: HealthItem[], L: Say, now = Date.now(), d?: Descriptor): RowState {
  if (c.status === "DISABLED") return { tone: "off", label: L("중지됨", "Stopped") };
  if (c.checks?.authentication_only && !Object.keys(c.plans).length) return { tone: "ok", label: L("계정 연결됨", "Account connected"),
    note: L("검사 위치와 읽기 권한은 콘텐츠 연결에서 선택합니다", "Select locations and read access under content connections") };
  if (c.status === "ACTIVE" && Object.keys(c.plans).length && !enabledPurposes(c).length) return { tone: "off",
    label: L("기능 모두 중지", "All features off"), note: L("인증 연결과 설정은 유지됩니다", "Sign-in and settings are retained"), fix: "resume" };
  // Made before people signed in through the company IdP: whether to stop it is the admin's call.
  if (c.sign_in_problem) return { tone: "warn", label: L("확인 필요", "Needs attention"),
    note: L("로그인에 쓰는 IdP가 아닌 사람 목록입니다 · 로그인 IdP를 사람 목록으로 연결하고 이 연동은 해제하세요",
      "This people directory is not the IdP people sign in with · connect the sign-in IdP and disconnect this one") };
  // A certificate CreMore made renews itself; one that expired, or whose renewal failed, needs a person.
  const made = c.status === "ACTIVE" ? generatedOf(c) : null;
  if (made) {
    const days = Math.ceil((Date.parse(made.not_after) - now) / 86_400_000);
    if (days <= 0) return { tone: "warn", label: L("확인 필요", "Needs attention"),
      note: L("인증서가 만료됐습니다 · 새 인증서를 만들어 앱 등록에 올리세요", "The certificate expired · make a new one and upload it to the app registration"), fix: "reauth" };
    if (c.checks.renewal?.state === "FAILED" && c.checks.renewal.action !== "retire") return { tone: "warn", label: L("확인 필요", "Needs attention"),
      note: L(`인증서 자동 교체 실패 · ${days}일 뒤 만료 · ${renewalText(c.checks.renewal.code, L)}`,
        `Certificate renewal failed · expires in ${days} day${days === 1 ? "" : "s"} · ${renewalText(c.checks.renewal.code, L)}`), fix: "reauth" };
  }
  // A token that renews itself (GitLab) and could not: reading its expiry, or the rotation.
  const renewal = c.status === "ACTIVE" ? c.checks.renewal : null;
  if (renewal?.state === "FAILED" && renewal.action !== "retire") return { tone: "warn", label: L("확인 필요", "Needs attention"),
    note: `${renewal.action === "inspect" ? L("토큰 확인 실패", "Token check failed") : L("자동 교체 실패", "Renewal failed")} · ${renewalText(renewal.code, L)}`, fix: "reauth" };
  const results = checkItems(c, c.purposes.filter(p => c.feature_enabled?.[p] !== false), d);
  const missing = results.filter(item => item.status === "MISSING").length;
  if (c.status === "CHECKING" || (c.checks.job_id && !checked(c) && c.checks.requested_at))
    return { tone: "running", label: L("권한 확인 중", "Checking access") };
  if (c.status === "DRAFT") return { tone: "setup", label: L("설정 중", "Setting up"), note: L("권한을 아직 확인하지 않았습니다", "Access has not been checked yet"), fix: "resume" };
  const summary = checkSummary(results);
  if (c.checks.error || summary === "error" || summary === "unreported") return {
    tone: c.status === "CHECKED" ? "setup" : "warn", label: L("확인 필요", "Needs attention"),
    note: summary === "unreported" && !c.checks.error ? L("필수 권한을 확인하지 못했습니다 · 다시 확인하세요", "Required access is unverified · check again")
      : L("권한 확인에 실패했습니다 · 다시 확인하세요", "Access check failed · check again"),
    fix: c.status === "CHECKED" ? "resume" : "recheck",
  };
  const acting = c.purposes.length === 1 && c.purposes[0] === "remediation";  // used by approved plans only
  const shared = sharedNote(c, L);  // on a row still being set up, its own line (page.tsx) says it
  if (c.status === "CHECKED") return { tone: "setup", label: L("설정 중", "Setting up"),
    note: acting ? (missing ? L(`권한 ${missing}개가 없습니다 · 켜면 승인된 조치에 씁니다`, `${missing} permission${missing > 1 ? "s" : ""} missing · turn it on for approved actions`)
      : L("권한을 확인했습니다 · 켜면 승인된 조치에 씁니다", "Access checked · turn it on for approved actions"))
      : missing ? L(`권한 ${missing}개가 없습니다 · 수집 범위를 정하면 시작합니다`, `${missing} permission${missing > 1 ? "s" : ""} missing · starts once you choose what to collect`)
        : L("권한을 확인했습니다 · 수집 범위를 정하면 시작합니다", "Access checked · starts once you choose what to collect"), fix: "resume" };
  const worst = (states: HealthItem["auth_state"][]) => items.find(item => states.includes(item.auth_state));
  const reauth = worst(["REAUTH_REQUIRED", "SECRET_UNAVAILABLE"]);
  if (reauth) return { tone: "warn", label: L("확인 필요", "Needs attention"), note: failureText(reauth.auth_reason, L) || L("다시 인증해야 합니다", "Sign in again"), fix: "reauth" };
  const expiring = worst(["EXPIRING"]);
  if (expiring) {
    const days = expiring.expires_at ? Math.max(0, Math.ceil((Date.parse(expiring.expires_at) - now) / 86_400_000)) : null;
    return { tone: "warn", label: L("확인 필요", "Needs attention"),
      note: days !== null ? L(`연동 인증이 ${days}일 뒤 만료됩니다`, `The integration's sign-in expires in ${days} day${days === 1 ? "" : "s"}`) : failureText("AUTH_EXPIRING", L), fix: "reauth" };
  }
  const limited = worst(["PERMISSION_LIMITED"]) ?? items.find(item => item.last_status === "FAILED" || item.last_status === "PARTIAL");
  if (limited) return { tone: "partial", label: L("일부 실패", "Partly failed"),
    note: limited.auth_state === "PERMISSION_LIMITED" ? L("권한이 모자라 일부를 읽지 못했습니다", "Some reads were refused for missing permissions")
      : limited.last_status === "PARTIAL" ? L("마지막 수집이 일부만 끝났습니다", "The last run finished partly")
        : L(`마지막 수집이 실패했습니다${limited.last_failure_code ? ` · ${limited.last_failure_code}` : ""}`, `The last run failed${limited.last_failure_code ? ` · ${limited.last_failure_code}` : ""}`), fix: "logs" };
  if (missing && checked(c)) return { tone: "warn", label: L("확인 필요", "Needs attention"),
    note: L(`권한 확인에서 ${missing}개가 없었습니다`, `${missing} permission${missing > 1 ? "s were" : " was"} missing in the check`), fix: "recheck" };
  if (shared) return { tone: "warn", label: L("확인 필요", "Needs attention"), note: shared, fix: "credential" };
  const collecting = items.filter(item => item.auth_state !== "DISABLED");
  if (collecting.length && collecting.every(item => !item.last_success_at && item.last_status === "NOT_COLLECTED"))
    return { tone: "running", label: L("수집 중", "Collecting"), note: L("첫 수집을 기다리고 있습니다", "Waiting for the first run") };
  return { tone: "ok", label: L("정상", "Healthy") };
}

/* ---------- what a connection found ---------- */

// Issued inventory providers as the catalog names them (credential_records._ISSUER plus AWS).
const ISSUER: Record<string, string> = { aws_iam: "aws", azure_entra: "azure", azure_resource_manager: "azure", azure_key_vault: "azure" };
// Content source types by the catalog provider that scans them.
const SCANNED: Record<string, string> = { s3: "aws", gcp: "gcp", azure_blob: "azure" };

export const issuerProvider = (provider: string) => ISSUER[provider] ?? provider;
export const scanProvider = (sourceType: string) => SCANNED[sourceType] ?? sourceType;

/** The issuers whose listed credentials a connection's inventory brings: the collections its inventory
 * types match, where the type applies to the connection's target (a Microsoft connection names an Azure
 * DevOps organization for its PATs). */
export function inventoryProviders(d: Descriptor | undefined, c: Pick<ProviderConnection, "provider" | "target">): Set<string> {
  const out = new Set([c.provider]);
  for (const type of d?.purposes.inventory?.types ?? []) {
    if (!applies(type, c.target)) continue;
    for (const rule of type.match ?? []) for (const provider of [rule.provider ?? []].flat()) out.add(issuerProvider(provider));
  }
  return out;
}

export function inventoryCount(d: Descriptor | undefined, c: Pick<ProviderConnection, "provider" | "target">, records: CredentialRecord[] | undefined) {
  const issuers = inventoryProviders(d, c);
  return (records ?? []).filter(r => r.issued && issuers.has(issuerProvider(r.issued.provider))).length;
}

export function exposureCount(provider: string, records: CredentialRecord[] | undefined) {
  return (records ?? []).filter(r => r.exposed && r.status !== "fp" && r.exposures.some(e => e.current && scanProvider(e.source_type) === provider)).length;
}

/* ---------- schedules ---------- */

export const SCHEDULES: { minutes: number; label: [string, string] }[] = [
  { minutes: 5, label: ["5분마다", "Every 5 minutes"] },
  { minutes: 15, label: ["15분마다", "Every 15 minutes"] },
  { minutes: 30, label: ["30분마다", "Every 30 minutes"] },
  { minutes: 60, label: ["1시간마다", "Every hour"] },
  { minutes: 360, label: ["6시간마다", "Every 6 hours"] },
  { minutes: 1440, label: ["매일", "Daily"] },
  { minutes: 10080, label: ["매주", "Weekly"] },
  { minutes: 0, label: ["직접 실행할 때만", "Only when run manually"] },
];

export function scheduleLabel(minutes: number, L: Say) {
  const known = SCHEDULES.find(item => item.minutes === minutes);
  if (known) return L(...known.label);
  return minutes % 60 === 0 ? L(`${minutes / 60}시간마다`, `Every ${minutes / 60} hours`) : L(`${minutes}분마다`, `Every ${minutes} minutes`);
}

/* ---------- refusals ---------- */

const CODES: Record<string, [string, string]> = {
  AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED: ["API와 worker에 EC2·ECS·EKS 역할 또는 온프레미스 워크로드 신원을 연결하고 AWS 신원 설정에서 승인하세요. 개인 SSO·고정 키는 새 서버 연결에 사용할 수 없습니다.", "Configure and approve a server workload identity for the API and worker (EC2, ECS, EKS, or on-premises workload federation). Personal SSO and static keys cannot create a new server connection."],
  AWS_ORGANIZATIONS_ACCESS_DENIED: ["AWS Organizations 계정 목록 조회가 거절되었습니다. 위임 관리자 계정(권장) 또는 관리 계정의 서버 역할에 organizations:ListAccounts와 조직·OU 구조를 읽는 DescribeOrganization·ListRoots·ListAccountsForParent·ListOrganizationalUnitsForParent가 필요합니다. 목록 조회 없이 연결하려면 인증 단계의 ‘계정 ID로 직접 연결’을 사용하세요.", "AWS Organizations account listing was denied. The server role in a delegated administrator account (preferred) or the management account needs organizations:ListAccounts and, to read the organization's OU structure, DescribeOrganization, ListRoots, ListAccountsForParent and ListOrganizationalUnitsForParent. To connect without listing the organization, use ‘Connect by account ID’ in the authentication step."],
  AWS_ORGANIZATIONS_NOT_AVAILABLE: ["Organizations 목록은 조회하지 못했습니다. 기존 등록 계정과 현재 서버의 계정을 보여 줍니다. 이 목록은 조직 전체가 아니며, 선택한 계정의 수집 역할 접근을 다음 단계에서 확인합니다.", "Organizations could not be listed. Showing registered accounts and the server's account. This is not the full organization; collection-role access is checked for the accounts you select."],
  ONBOARDING_SCHEDULE_INVALID: ["수집 주기는 0(수동) 또는 허용된 범위의 5분 이상으로 설정하세요.", "Use 0 for manual collection, or an allowed interval of at least 5 minutes."],
  SCAN_SCHEDULES_DISABLED: ["설치 관리자가 정기 수집을 꺼 두었습니다. 수동 수집을 선택하거나 설치 설정을 확인하세요.", "Scheduled collection is disabled by the installation. Choose manual collection or review installation settings."],
  AWS_MEMBER_ROLE_SETUP_REQUIRED: ["선택한 계정에 수집용 멤버 역할 또는 StackSet과 동일한 ExternalId를 먼저 구성하세요.", "Configure the scanner member role or StackSet in the selected account with the matching ExternalId first."],
  AWS_ACCOUNT_SETTINGS_CHANGED: ["역할·승인·조직 설정이 변경되었습니다. 다시 인증하고 계정 목록을 조회하세요.", "Role, approval, or organization settings changed. Authenticate and list accounts again."],
  AWS_ACCOUNT_NOT_DISCOVERED: ["인증된 계정 목록에서 확인되지 않은 계정입니다. 목록을 다시 조회하세요.", "This account was not confirmed in the authenticated list. Refresh the list."],
  AWS_ORGANIZATIONS_RESPONSE_INVALID: ["AWS 조직 목록 응답을 확인하지 못했습니다. 잠시 뒤 다시 조회하세요.", "The AWS organization list could not be verified. Retry shortly."],
  AWS_ORGANIZATIONS_PAGINATION_INVALID: ["AWS 조직 목록의 다음 페이지를 확인하지 못했습니다. 목록을 다시 조회하세요.", "The next AWS organization page could not be verified. Refresh the list."],
  AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS: ["이 인증 방식은 기존 연결 유지용입니다. 서버에서 지속 실행할 수 있는 역할·워크로드·앱 인증을 선택하세요.", "This sign-in method is only for maintaining an existing connection. Choose a role, workload identity, or app credential suitable for unattended server use."],
  TARGET_EDIT_NO_ACTIVE_FEATURES: ["수집 기능이 모두 꺼져 있습니다. 연동 설정에서 필요한 기능을 먼저 켠 뒤 범위를 수정하세요.", "All collection features are off. Turn on a feature in integration settings before editing its scope."],
  TARGET_EDIT_PAUSED_FEATURE: ["꺼진 기능의 범위는 유지됩니다. 해당 기능을 먼저 켠 뒤 범위를 수정하세요.", "An off feature keeps its scope. Turn it on before editing its scope."],
  // Continuing with the ready features (sessions.inspect narrowing) keeps what an edited integration already runs.
  TARGET_EDIT_KEEP_FEATURES: ["이미 수집 중인 기능은 보류할 수 없습니다. 권한을 부여한 뒤 다시 확인하세요.", "A feature that is already collecting cannot be held. Grant its access and check again."],
  ONBOARDING_TARGETS_INVALID: ["선택한 대상이 이 초안의 목록에 없거나 남은 기능에 쓰이지 않습니다. 대상을 다시 고르세요.", "A selected target is not in this draft's list or serves none of the remaining features. Choose the targets again."],
  AUTH_FIRST_NOT_SUPPORTED: ["이 인증 방식은 자동 대상 조회를 지원하지 않습니다. 기존 설정을 사용하세요.", "Automatic discovery is unavailable for this sign-in method. Use existing setup."],
  AUTH_FIRST_ENTERPRISE_DISCOVERY_UNSUPPORTED: ["이 인증으로 Enterprise 목록을 자동 조회할 수 없습니다. 기존 설정에서 연결하세요.", "Enterprise discovery is unavailable for this credential. Use existing setup."],
  AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED: ["세분화 PAT의 조직 자동 조회는 지원하지 않습니다. 기존 설정에서 조직을 지정하세요.", "Organization discovery is unavailable for fine-grained PATs. Specify the organization in existing setup."],
  ONBOARDING_SESSION_EXPIRED: ["인증 초안이 만료되었습니다. 인증부터 다시 시작하세요.", "This draft expired. Start authentication again."],
  ONBOARDING_SESSION_CHANGED: ["초안이 변경되었습니다. 다시 열어 최신 선택을 확인하세요.", "The draft changed. Reopen it to review the latest selection."],
  ONBOARDING_TARGET_LIMIT: ["대상 목록 한도에 도달했습니다. 더 좁은 권한 범위의 연결을 사용하세요.", "The target limit was reached. Use a credential with a narrower scope."],
  ONBOARDING_REQUEST_LIMIT: ["목록 조회의 호출 한도에 도달했습니다. 범위를 줄여 다시 확인하세요.", "The listing request limit was reached. Narrow the scope and retry."],
  ONBOARDING_TIME_LIMIT: ["목록 조회 시간이 초과되었습니다. 잠시 뒤 다시 확인하세요.", "Listing timed out. Try again shortly."],
  ONBOARDING_RESOURCE_LIMIT: ["검사 대상 목록 한도에 도달했습니다. 상위 대상 수를 줄여 다시 확인하세요.", "The resource limit was reached. Select fewer parent targets and retry."],
  ONBOARDING_EACH_FEATURE_NEEDS_TARGET: ["선택한 기능마다 대상을 하나 이상 고르세요.", "Choose at least one target for each selected feature."],
  ONBOARDING_EACH_TARGET_NEEDS_RESOURCES: ["연동 대상마다 검사할 항목을 하나 이상 고르세요.", "Choose at least one scan resource for each target."],
  ONBOARDING_MULTIPLE_SCOPES_USE_EDITOR: ["이 연결은 검사 범위가 여러 개입니다. 기존 검사 대상 화면에서 수정하세요.", "This connection has multiple scope profiles. Use the existing scan target editor."],
  ONBOARDING_EXISTING_SCOPE_NOT_LISTED: ["기존 검사 대상 일부를 조회하지 못했습니다. 접근 권한을 확인하거나 기존 검사 대상 화면에서 제외할 항목을 직접 선택하세요.", "Some existing scan targets were not listed. Check access or explicitly remove them in the existing scan target editor."],
  ONBOARDING_EXISTING_TARGET_NOT_LISTED: ["이 연결이 지금 수집하는 대상 일부가 이번 목록에 없습니다. 대상을 더 불러오거나 공급자에서 설치·권한을 확인하세요. 그 대상을 그만 수집하려면 '수집 범위·인증 설정' → '유지할 기존 대상'에서 직접 빼세요.", "Some targets this integration collects from are not in this listing. Load more targets, or check the installation and access at the provider. To stop collecting one, remove it yourself under 'Collection scope and sign-in' → 'Existing targets to keep'."],
  TARGETS_REQUIRE_DIFFERENT_OPTIONS: ["선택한 대상의 옵션 구조가 다릅니다. 같은 종류의 대상끼리 연결하세요.", "These targets require different options. Connect targets of the same kind together."],
  REQUIRED_PERMISSIONS_NOT_GRANTED: ["필수 권한을 확인하지 못했습니다. 권한 결과를 확인하고 다시 검사하세요.", "Required access is unverified. Review the results and check again."],
  PERMISSION_CHECK_REQUIRED: ["현재 선택의 권한을 다시 확인해야 합니다.", "Check access again for the current selection."],
  SCOPE_CATALOG_RECHECK_REQUIRED: ["인증 또는 목록이 변경·만료되었습니다. 목록을 새로 고치고 권한을 다시 확인하세요.", "Authentication or the catalog changed or expired. Refresh the list and recheck access."],
  VAULT_MOUNTS_ACCESS_DENIED: ["Vault의 sys/mounts 목록 조회가 거절되었습니다. 이 경로의 read 권한을 확인하세요.", "Vault denied the sys/mounts listing. Check read access to that path."],
  AWS_REGIONS_ACCESS_DENIED: ["현재 서버 역할의 활성 리전 조회(ec2:DescribeRegions)가 거절되었습니다. 인증 단계의 ‘CreMore 신원에 읽기 정책 넣기’를 확인하세요. 권한이 이미 있다면 권한 경계·조직 정책도 확인하세요.", "Active-region listing (ec2:DescribeRegions) by the current server role was denied. Check ‘Give CreMore’s identity the read policy’ in the authentication step. If access is already granted, also check permission boundaries and organization policies."],
  GCP_PROJECT_LIST_HTTP_403: ["프로젝트 목록 조회(projects.search)가 거절되었습니다. 서비스 계정(ADC)의 프로젝트나 Google 로그인 앱의 프로젝트에 Cloud Resource Manager API가 켜져 있는지, 연결 신원의 프로젝트 접근과 조직 정책을 확인하세요.", "Project discovery (projects.search) was denied. Check that the Cloud Resource Manager API is enabled in the service account's project (ADC) or the Google sign-in app's project, and the connected identity's project access and organization policy."],
  GITHUB_ORGANIZATIONS_HTTP_403: ["조직 목록 조회(GET /user/orgs)가 거절되었습니다. classic PAT의 read:org 및 조직 접근·SSO 승인을 확인하세요.", "Organization listing (GET /user/orgs) was denied. Check the classic PAT’s read:org, organization access and SSO authorization."],
  GITHUB_TOKEN_READ_ORG_REQUIRED: ["이 classic PAT로는 조직 목록(GET /user/orgs)을 읽을 수 없습니다. 토큰에 read:org 범위를 추가하세요. 엔터프라이즈 SSO 신원을 읽으려면 read:enterprise도 필요합니다.", "This classic PAT cannot list organizations (GET /user/orgs). Add the read:org scope; reading enterprise SSO identities also needs read:enterprise."],
  GITHUB_HOST_INVALID: ["선택한 GitHub 제품의 HTTPS 호스트를 입력하세요. GHE.com은 전용 *.ghe.com 주소, Server는 자체 서버 주소를 사용합니다.", "Enter the HTTPS host for the selected GitHub product: its dedicated *.ghe.com address or self-hosted Server address."],
  GITHUB_ORGANIZATIONS_HTTP_401: ["GitHub가 조직 목록 인증을 거절했습니다. 토큰 또는 App 인증정보를 다시 확인하세요.", "GitHub rejected authentication for organization listing. Check the token or App credential."],
  GITHUB_ORGANIZATIONS_HTTP_404: ["GitHub 조직 목록 경로를 찾지 못했습니다. 서버 주소와 접근 권한을 확인하세요.", "The GitHub organization listing endpoint was not found. Check the server address and access."],
  GITHUB_ORGANIZATIONS_REQUEST_FAILED: ["GitHub 조직 목록을 읽지 못했습니다. 잠시 뒤 다시 확인하세요.", "The GitHub organization list could not be read. Try again shortly."],
  GITHUB_ORGANIZATIONS_INVALID: ["GitHub 조직 목록 또는 요청 형식을 확인하지 못했습니다. 목록을 다시 불러오세요.", "The GitHub organization list or request is invalid. Reload the list."],
  GITHUB_ORGANIZATIONS_LIMIT: ["GitHub 조직 목록의 조회 한도에 도달했습니다. 더 좁은 조직 범위의 인증을 사용하세요.", "The GitHub organization listing limit was reached. Use a credential with a narrower organization scope."],
  GITHUB_APP_IDENTITY_MISMATCH: ["입력한 App ID와 개인 키의 App이 다릅니다. 같은 App의 정보를 입력하세요.", "The App ID and private key belong to different Apps. Enter credentials from the same App."],
  GITHUB_APP_ID_INVALID: ["GitHub App 설정의 App ID 또는 Client ID를 입력하세요.", "Enter the App ID or Client ID from the GitHub App settings."],
  GITHUB_TOKEN_INVALID: ["GitHub 개인 액세스 토큰 형식이 아닙니다. 발급받은 PAT를 그대로 입력하세요.", "This is not a valid GitHub personal access token format. Enter the PAT as issued."],
  WRITE_REQUIRED: ["조직 토큰 접근을 취소할 쓰기 권한이 필요합니다. 조치 전용 App의 권한을 확인하세요.", "Write access is required to revoke organization token access. Check the acting App's permissions."],
  GITHUB_ENTERPRISE_SEALED_CREDENTIAL_REQUIRED: ["다른 조직에 설치하려면 이 연결에 App 개인 키를 직접 저장해야 합니다. Vault 참조는 사용할 수 없습니다.", "Installing on other organizations requires an App private key stored directly in this connection, not a Vault reference."],
  GITLAB_GROUPS_LIST_HTTP_403: ["그룹 목록 조회(GET /groups)가 거절되었습니다. 토큰의 read_api 또는 api와 그룹 접근을 확인하세요.", "Group listing (GET /groups) was denied. Check read_api or api and group access for the token."],
  GITLAB_PROJECTS_LIST_HTTP_403: ["프로젝트 목록 조회(GET /projects)가 거절되었습니다. 토큰의 read_api 또는 api와 프로젝트 접근을 확인하세요.", "Project listing (GET /projects) was denied. Check read_api or api and project access for the token."],
  AZURE_TARGET_LIST_ACCESS_DENIED: ["Azure Resource Manager의 대상 목록 조회가 거절되었습니다. 해당 구독의 Reader 역할과 조건을 확인하세요.", "Azure Resource Manager denied target listing. Check Reader access and conditions on the subscription."],
  MALFORMED_RESPONSE: ["공급자의 응답 형식을 확인할 수 없습니다.", "The provider returned an unexpected response."],
  AUTHENTICATION_REQUIRED: ["인증을 확인하지 못했습니다. 인증정보와 접속 대상을 확인하세요.", "Authentication is unverified. Check the credential and sign-in target."],
  PROVIDER_UNKNOWN: ["지원하지 않는 서비스입니다.", "That service is not supported."],
  EDITION_UNKNOWN: ["지원하지 않는 제품입니다.", "That edition is not supported."],
  // The GitHub App start (startGitHubApp): a refusal before the admin leaves for GitHub, read where it was started.
  GITHUB_APP_STORAGE_UNAVAILABLE: ["이 브라우저가 진행 상태를 저장하지 못해 GitHub로 이동하지 않았습니다. 이 사이트의 저장소 사용(시크릿 창·차단 설정)을 허용한 뒤 다시 시도하세요.",
    "This browser could not store the setup's progress, so it did not leave for GitHub. Allow site storage for this console (private windows or blocking settings may prevent it) and try again."],
  GITHUB_APP_RESPONSE_INVALID: ["서버가 알려 준 GitHub 주소가 이 조직의 App 만들기 페이지가 아니어서 이동하지 않았습니다. GitHub 서버 주소와 조직 이름을 확인하세요.",
    "The GitHub address the server returned is not this organization's new App page, so the console did not go there. Check the GitHub server address and the organization name."],
  GITHUB_APP_REQUEST_INVALID: ["App 만들기 요청이 올바르지 않습니다. 이 창을 닫고 연동 화면에서 다시 시작하세요.", "The App setup request is not valid. Close this window and start again from the integrations screen."],
  GITHUB_APP_BROWSER_KEY_INVALID: ["이 브라우저의 설정 키를 확인하지 못했습니다. 페이지를 새로 고친 뒤 다시 시작하세요.", "This browser's setup key could not be verified. Reload the page and start again."],
  GITHUB_ORGANIZATION_INVALID: ["조직 이름은 GitHub 주소의 조직 부분만 입력하세요(github.com/acme이면 acme).", "Enter only the organization part of its GitHub address (acme for github.com/acme)."],
  GITHUB_APP_SIGN_IN_EXPIRED: ["CreMore 로그인이 만료됐습니다. 다시 로그인한 뒤 다시 시작하세요.", "Your CreMore sign-in expired. Sign in again, then start again."],
  GITHUB_APP_UNAVAILABLE: ["GitHub에 연결하지 못했습니다. 잠시 뒤 다시 시도하세요.", "GitHub could not be reached. Try again shortly."],
  EDITION_RETIRED_FOR_NEW_CONNECTIONS: ["새 연결에서는 사용 중인 제품·요금제를 선택하세요. 기존 연결은 그대로 관리할 수 있습니다.", "Select your current product or plan for a new connection. Existing connections can still be maintained."],
  PURPOSES_INVALID: ["수집 기능을 하나 이상 고르세요.", "Choose at least one feature."],
  AUTH_METHOD_NOT_FOR_PURPOSES: ["고른 기능을 이 인증 방식으로 함께 쓸 수 없습니다.", "This sign-in method cannot serve the chosen features together."],
  ACTIVE_PURPOSE_CANNOT_BE_REMOVED: ["이미 수집 중인 기능은 여기서 해제할 수 없습니다.", "A feature already collecting cannot be removed here."],
  NAME_INVALID: ["이름은 120자 이내로 입력하세요.", "Use a name of up to 120 characters."],
  CREDENTIAL_REFERENCE_NOT_ALLOWED: ["이 방식은 Vault 참조를 받지 않습니다. 값을 직접 입력하세요.", "This method does not take a Vault reference. Enter the value."],
  CREDENTIAL_REFERENCE_INVALID: ["vault://경로 형식으로 입력하세요.", "Enter it as vault://path."],
  CREDENTIAL_FIELD_UNKNOWN: ["이 방식에 없는 입력이 있습니다.", "It has a field this method does not take."],
  CREDENTIAL_FIELD_INVALID: ["입력한 인증 정보의 형식이 맞지 않습니다.", "The credential is not in the expected format."],
  CREDENTIAL_INVALID: ["입력한 인증 정보의 형식이 맞지 않습니다.", "The credential is not in the expected format."],
  PROVIDER_NOT_READY: ["이 설치는 아직 이 연동을 받을 수 없습니다.", "This installation cannot take this integration yet."],
  PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP: ["팀 설치의 사람 목록은 로그인에 쓰는 IdP(같은 조직·테넌트·렐름)로만 연결합니다.",
    "A team install connects people only from the IdP people sign in with (the same organization, tenant or realm)."],
  PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN: ["로그인 IdP를 CreMore가 사람 목록을 읽는 IdP로 알아보지 못해, 팀 설치에서는 사람 목록을 연결하지 않습니다.",
    "CreMore cannot read people from the sign-in IdP, so a team install connects no people directory."],
  KEYCLOAK_ADDRESS_INVALID: ["Keycloak 주소는 https://호스트[:포트]까지만 넣고, /auth 같은 경로는 경로 접두어 칸에 넣으세요.",
    "Enter the Keycloak address as https://host[:port] only; a path such as /auth goes in the path prefix field."],
  AWS_SCANNER_IDENTITY_NOT_APPROVED: ["먼저 CreMore가 쓸 AWS 신원을 승인하세요.", "Approve the AWS identity CreMore uses first."],
  RUNTIME_IDENTITY_IS_ONE_ACCOUNT: ["이 설치의 AWS 신원으로는 계정 하나만 연결합니다.", "The installation's own AWS identity connects one account."],
  AWS_ACCOUNT_IDS_INVALID: ["계정 ID는 12자리 숫자로 입력하세요.", "Enter 12-digit account IDs."],
  AWS_PERMISSION_SET_INVALID: ["권한 세트 이름을 확인하세요.", "Check the permission set name."],
  AWS_REGIONS_INVALID: ["리전 이름을 확인하세요.", "Check the region names."],
  // The vault comparison's value-reader role (cremore_aws_provider.onboarding value_reader_items, aws_sessions.value_reader).
  VALUE_READER_NEEDS_ROLE_ACCESS: ["값 읽기 역할은 계정별 수집 역할로 연결한 계정에서만 씁니다. 다른 접근 방식이면 값 읽기 역할을 끄세요.", "The value-reader role works only for accounts connected with per-account collection roles. Turn it off for other access methods."],
  VALUE_READER_ASSUME_DENIED: ["수집 역할이 값 읽기 역할을 맡지 못했습니다. 스택을 EnableVaultValueRead=true로 배포했는지, 역할 이름과 ExternalId가 맞는지 확인하세요.", "The collection role could not assume the value-reader role. Check that the stack was deployed with EnableVaultValueRead=true and that the role name and ExternalId match."],
  VALUE_READER_ROLE_INVALID: ["값 읽기 역할 이름이 IAM 역할 이름 형식(영문·숫자와 +=,.@_-, 64자 이내)이 아닙니다.", "The value-reader role name is not an IAM role name (letters, digits and +=,.@_-, up to 64)."],
  VALUE_READER_POLICY_DENIES: ["값 읽기 역할의 정책이 적은 시크릿·경로 가운데 하나 이상을 허용하지 않습니다. 스택의 VaultSecretArns·VaultParameterPathArns에 넣고 갱신하세요.", "The value-reader role's policy does not allow one or more of the listed secrets or paths. Add them to the stack's VaultSecretArns or VaultParameterPathArns and update the stack."],
  VALUE_READER_POLICY_EXPLICITLY_DENIED: ["권한 경계, 조직의 SCP 또는 다른 명시적 거부 정책이 값 읽기 역할의 이 읽기를 막습니다. 스택 목록에 더해도 풀리지 않으므로 그 거부를 고칩니다.", "A permissions boundary, an organization SCP or another explicit deny blocks this read for the value-reader role. Adding it to the stack's lists does not lift it; change that deny."],
  VALUE_READER_AUTOMATION_DISABLED: ["값 읽기 역할로 읽는 금고의 주기 수집은 설치의 AWS 자동 수집 설정이 이 계정을 포함할 때만 돕니다. AWS 설정에서 자동 수집을 켜고 이 계정을 넣습니다. 요청할 때의 수집은 그대로 됩니다.", "Scheduled reads through the value-reader role run only while the installation's AWS automatic collection includes this account. Turn automatic collection on in the AWS settings and include the account. On-demand collection still runs."],
  AWS_VALUE_READER_POLICY_TOO_LARGE: ["이 계정의 시크릿 ARN·Parameter Store 경로·KMS 키가 값 읽기 역할 정책의 IAM 한도(10,240자)를 넘습니다. 보통 길이의 시크릿은 계정당 30개 정도 들어갑니다.", "This account's secret ARNs, Parameter Store paths and KMS keys exceed IAM's 10,240-character limit for the value-reader role's policy. About 30 secrets of usual length fit per account."],
  AWS_PARAMETER_PATH_INVALID: ["Parameter Store 경로는 구간마다 영문·숫자와 . _ - 만 쓸 수 있습니다(Parameter Store 이름과 CloudFormation 스택이 받는 문자). . 이나 .. 만으로 된 구간은 CreMore가 수집 범위로 받지 않습니다. /prod/app처럼 적으세요.", "Each segment of a Parameter Store path may use only letters, digits and . _ - (the characters Parameter Store names and the CloudFormation stack accept). CreMore does not take a segment of just . or .. as a collection scope. Enter a path such as /prod/app."],
  AWS_KMS_KEY_ARN_OUTSIDE_SCOPE: ["연결한 계정 밖의 KMS 키 ARN이 있습니다. 키는 그 키를 가진 계정의 스택에 적습니다.", "A KMS key ARN is outside the connected accounts. A key goes in the stack of the account that owns it."],
  VALUE_READER_SIMULATION_DENIED: ["수집 역할에 iam:SimulatePrincipalPolicy 권한이 없어 값 읽기 역할의 정책을 확인하지 못했습니다.", "The collection role lacks iam:SimulatePrincipalPolicy, so the value-reader role's policy could not be checked."],
  VALUE_READER_SIMULATION_FAILED: ["값 읽기 역할의 정책 시뮬레이션에 실패했습니다. 잠시 뒤 다시 확인하세요.", "Simulating the value-reader role's policy failed. Check again shortly."],
  VALUE_READER_SIMULATION_NEEDS_CONTEXT: ["정책에 시뮬레이션이 판단할 수 없는 조건이 있어 허용 여부를 확인하지 못했습니다.", "The policy has conditions the simulation cannot evaluate, so access could not be confirmed."],
  AWS_SECRET_ARNS_REQUIRED: ["값 읽기 역할은 적은 시크릿만 읽습니다. 이 계정의 시크릿 ARN을 하나 이상 적으세요.", "The value-reader role reads only listed secrets. List at least one secret ARN for this account."],
  AWS_SECRET_ARNS_INVALID: ["와일드카드 없이, 끝의 여섯 글자까지 포함한 Secrets Manager 시크릿 전체 ARN을 적으세요.", "Enter full Secrets Manager secret ARNs, including the six-character suffix, without wildcards."],
  AWS_SECRET_ARN_OUTSIDE_SCOPE: ["연결한 계정이나 고른 리전 밖의 시크릿 ARN이 있습니다.", "A secret ARN is outside the connected accounts or the chosen regions."],
  AWS_KMS_KEY_ARNS_INVALID: ["KMS 키 ARN(arn:…:kms:리전:계정:key/키 ID)을 적으세요. 별칭은 쓸 수 없습니다.", "Enter KMS key ARNs (arn:…:kms:region:account:key/key-id). Aliases are not allowed."],
  VALUE_READER_REQUIRES_AWS_SERVER_COLLECTION: ["값 읽기 역할은 AWS Secrets Manager·Parameter Store 서버 수집에서만 씁니다.", "A value-reader role applies only to AWS Secrets Manager or Parameter Store server collection."],
  VALUE_READER_REQUIRES_SECRET_ARNS: ["값 읽기 역할로 읽는 Secrets Manager 수집에는 시크릿 ARN이 있어야 합니다.", "A Secrets Manager collection read by the value-reader role needs secret ARNs."],
  ACCOUNT_ALREADY_REGISTERED: ["다른 연동이 이미 이 AWS 계정을 쓰고 있습니다.", "Another integration already uses this AWS account."],
  ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS: ["이 AWS 계정은 다른 접근 방식으로 등록돼 있습니다.", "This AWS account is registered with another access mode."],
  RECORD_OWNED_BY_ANOTHER_CONNECTION: ["다른 연동이 이미 같은 대상을 쓰고 있습니다.", "Another integration already uses the same target."],
  CONTENT_SOURCE_ALREADY_EXISTS: ["같은 대상의 노출 검사가 이미 있습니다.", "An exposure scan of the same target already exists."],
  PROVIDER_CONNECTION_NOT_FOUND: ["연동을 찾을 수 없습니다. 목록을 새로 불러오세요.", "The integration was not found. Reload the list."],
  PROVIDER_CONNECTION_DISABLED: ["중지된 연동입니다. 먼저 다시 켜세요.", "This integration is stopped. Turn it on first."],
  PROVIDER_CONNECTION_NOT_CHECKED: ["권한 확인을 마친 뒤에 시작할 수 있습니다.", "Finish the access check first."],
  PROVIDER_CONNECTION_NOT_ACTIVE: ["수집 중인 연동에서만 수집 설정을 바꿀 수 있습니다.", "Collection settings change only on a collecting integration."],
  CONNECTION_REVISION_CONFLICT: ["수집 설정이 그사이 바뀌었습니다. 새로 불러온 뒤 다시 저장하세요.", "A collection changed in the meantime. Reload and save again."],
  COLLECTION_SPEC_INVALID: ["이 설정으로는 수집을 만들 수 없습니다. 입력한 값을 확인하세요.", "A collection cannot run with these settings. Check what you entered."],
  PROVIDER_CONNECTION_HAS_CHILDREN: ["수집 기록이 있는 연동은 지울 수 없습니다. 중지만 할 수 있습니다.", "An integration with collection records cannot be deleted, only stopped."],
  PROVIDER_CONNECTION_CHANGED: ["다른 사람이 먼저 바꿨습니다. 새로 불러온 뒤 다시 적용하세요.", "Someone changed it first. Reload and apply again."],
  AUTH_SETTINGS_FIXED_WHILE_IN_USE: ["연결된 수집이 있는 동안에는 인증 방식을 바꿀 수 없습니다.", "The sign-in method cannot change while collections use it."],
  GCP_VALUE_CHOICES_SET_BY_THE_PROJECT_COLLECTION: ["이 프로젝트의 값 읽기 선택은 먼저 시작한 수집과 같아야 합니다.", "Value reading must match the project's existing collection."],
  GCP_KEEPING_VALUES_NEEDS_READING_THEM: ["값을 보관하려면 값 읽기도 켜야 합니다.", "Keeping values needs reading them too."],
  GCP_DISCOVERY_IS_INVENTORY_ONLY: ["조직·폴더 범위는 발급 목록 수집만 씁니다.", "An organization or folder scope is for the issuance inventory only."],
  GCP_SIGN_IN_REQUIRED: ["먼저 Google에서 승인하세요.", "Approve in Google first."],
  GCP_SIGN_IN_CONNECTION_REQUIRED: ["Google 로그인 방식의 연동에서만 승인할 수 있습니다.", "Only a Google sign-in integration can be approved."],
  GCP_OAUTH_SETUP_REQUIRED: ["Google 로그인 앱이 설정되지 않았습니다. 인증 단계에서 앱을 등록하세요. 서버 설정으로 고정한 앱은 관리자가 GCP_OAUTH_* 설정을 확인해야 합니다.", "The Google sign-in app is not set up. Register it in the authentication step. For a server-pinned app, an administrator must check GCP_OAUTH_* settings."],
  GCP_OAUTH_STATE_INVALID: ["Google 승인 세션이 맞지 않습니다. 다시 승인하세요.", "The Google approval session does not match. Approve again."],
  GITLAB_INSTANCE_SCOPE_IS_INVENTORY_ONLY: ["인스턴스 전체 범위는 발급 목록 수집만 씁니다.", "The whole-instance scope is for the issuance inventory only."],
  GITLAB_INSTANCE_SCOPE_NEEDS_SELF_MANAGED: ["인스턴스 전체 범위는 Self-Managed·Dedicated에서만 씁니다.", "The whole-instance scope needs Self-Managed or Dedicated."],
  GITHUB_AUDIT_TOKEN_NEEDS_AN_ENTERPRISE: ["감사 로그 토큰은 엔터프라이즈를 지정할 때만 씁니다.", "The audit log token needs an enterprise."],
  GITHUB_ENTERPRISE_CREDENTIALS_READ_REQUIRED: ["엔터프라이즈에 설치된 App에 Enterprise credentials: 읽기 권한을 부여하고 변경을 승인하세요. 조직 설치 권한만으로는 전체 목록을 읽을 수 없습니다.", "Grant Enterprise credentials: read to the Enterprise installation and approve the change. Organization installation access alone cannot read the Enterprise inventory."],
  ENTERPRISE_INSTALLATION_PERMISSION_CONFIRMED: ["엔터프라이즈 설치의 자격증명 목록 읽기 권한을 확인했습니다.", "Credential inventory read access is confirmed on the Enterprise installation."],
  GITHUB_ENTERPRISE_EXPORT_EDITION_UNSUPPORTED: ["현재 확인된 전체 Export API는 Enterprise Cloud·GHE.com용입니다. 이 Server 버전의 지원을 확인할 수 없어 전체 목록을 활성화하지 않습니다. 조직 목록 수집은 별도로 사용할 수 있습니다.", "The verified full Export API is for Enterprise Cloud and GHE.com. This Server version is not verified, so full inventory cannot be enabled. Organization inventory remains available."],
  GITHUB_ENTERPRISE_AUDIT_TOKEN_REQUIRED: ["엔터프라이즈 감사 로그용 classic PAT(read:audit_log)를 인증 단계에 추가하세요.", "Add a classic PAT with read:audit_log for Enterprise audit logs in authentication."],
  ENTERPRISE_INSTALLATION_GITHUB_HTTP_404: ["이 App의 엔터프라이즈 설치를 찾을 수 없습니다. 조직 설치와 별도로 엔터프라이즈 계정에 설치하세요.", "The App's Enterprise installation was not found. Install it on the Enterprise account separately from its organization installation."],
  ENTERPRISE_INSTALLATION_GITHUB_HTTP_403: ["엔터프라이즈 설치 조회가 거절되었습니다. App 소유·설치와 관리자 승인 상태를 확인하세요.", "Enterprise installation lookup was denied. Check App ownership, installation and administrator approval."],
  ENTERPRISE_INSTALLATION_SUSPENDED: ["엔터프라이즈 App 설치가 중지되었습니다. GitHub에서 설치를 재개하세요.", "The Enterprise App installation is suspended. Resume it in GitHub."],
  INSTALLATION_NOT_AUTHORIZED: ["확인된 App 설치가 선택한 엔터프라이즈·조직과 일치하지 않습니다.", "The verified App installation does not match the selected Enterprise or organization."],
  GITHUB_AUDIT_TOKEN_MUST_BE_A_CLASSIC_PAT: ["감사 로그 토큰은 클래식 PAT여야 합니다.", "The audit log token must be a classic PAT."],
  GITHUB_TOKEN_DIGESTS_NEED_THE_AUDIT_TOKEN: ["토큰 digest는 감사 로그 토큰이 있을 때만 켤 수 있습니다.", "Token digests need the audit log token."],
  GITHUB_IDENTITY_ENTERPRISE_REQUIRED: ["엔터프라이즈의 SSO 신원을 읽으려면 연동 대상에 엔터프라이즈를 입력하세요.", "Reading the enterprise's SSO identities needs the enterprise in the target."],
  GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE: ["GHE.com의 사람 목록은 엔터프라이즈에서 읽습니다. 연동 대상에 엔터프라이즈를 입력하고 '조직 대신 엔터프라이즈의 SSO 신원 읽기'를 켜세요.", "On GHE.com people are read from the enterprise: enter the enterprise in the target and turn on reading the enterprise's SSO identities."],
  GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN: ["GitHub은 엔터프라이즈의 SSO 신원을 엔터프라이즈 소유자의 classic PAT에만 보여 줍니다. 사람 목록은 그 토큰(read:enterprise)으로 연결하세요.",
    "GitHub shows an enterprise's SSO identities only to an enterprise owner's classic PAT. Connect the people directory with that token (read:enterprise)."],
  BITBUCKET_API_TOKEN_EMAIL_REQUIRED: ["API 토큰과 함께 계정 이메일을 입력하세요.", "Enter the account e-mail with the API token."],
  VAULT_LOGIN_ROLE_AND_TOKEN_FILE_REQUIRED: ["역할과 토큰 파일을 입력하세요.", "Enter the role and the token file."],
  VAULT_TLS_CA_MUST_BE_A_PEM_CERTIFICATE: ["CA 인증서는 PEM 형식이어야 합니다.", "The CA certificate must be PEM."],
  EXTERNAL_VAULT_DECLARED_SCOPE_REQUIRED: ["대조할 경로 접두어를 입력하세요.", "Enter the path prefixes to compare."],
  AZURE_STORAGE_KEYS_NEED_THE_SUBSCRIPTION: ["스토리지 키 지문을 읽으려면 구독 ID가 필요합니다.", "Reading storage key fingerprints needs the subscription ID."],
  AZURE_STORAGE_ACCOUNT_REQUIRED: ["노출 검사에는 스토리지 계정이 필요합니다.", "Exposure scanning needs a storage account."],
  AZURE_EXPOSURE_TARGET_REQUIRED: ["노출 검사에는 스토리지 계정이나 Azure DevOps 프로젝트가 필요합니다.", "Exposure scanning needs a storage account or an Azure DevOps project."],
  AZURE_DEVOPS_ORGANIZATION_REQUIRED: ["Azure DevOps 프로젝트를 쓰려면 조직도 입력하세요.", "An Azure DevOps project needs its organization too."],
  AZURE_CLIENT_ID_INVALID: ["애플리케이션(클라이언트) ID는 GUID 형식입니다. 앱 등록 개요에서 복사하세요.", "The application (client) ID is a GUID. Copy it from the app registration's overview."],
  AZURE_TENANT_ID_INVALID: ["테넌트 ID는 GUID 형식입니다.", "The tenant ID is a GUID."],
  CREDENTIAL_NOT_GENERATED: ["이 방식은 CreMore가 인증서를 만들지 않습니다.", "CreMore does not make a certificate for this method."],
  AZURE_KEY_VAULT_REQUIRED: ["Secret 저장소 대조에는 Key Vault 이름이 필요합니다.", "Secret store comparison needs a Key Vault name."],
  NOTION_WORKSPACE_ID_REQUIRED: ["발급 목록 수집에는 워크스페이스 ID가 필요합니다.", "The issuance inventory needs the workspace ID."],
  CONFLUENCE_CLOUD_SPACE_ID_AND_WIKI_BASE_REQUIRED: ["Confluence Cloud는 /wiki 주소와 공간 ID가 필요합니다.", "Confluence Cloud needs the /wiki address and a space ID."],
  ATLASSIAN_OAUTH_CLIENT_INVALID: ["클라이언트 ID와 시크릿을 Atlassian 관리에서 복사한 그대로 입력하세요.", "Enter the client ID and secret as copied from Atlassian Administration."],
  OKTA_CLIENT_ID_INVALID: ["클라이언트 ID는 서비스 앱의 General 탭에서 복사하세요(예: 0oa…).", "Copy the client ID from the service app's General tab (0oa…)."],
  GOOGLE_WORKSPACE_DOMAIN_INVALID: ["기본 도메인을 acme.com처럼 입력하세요.", "Enter the primary domain, like acme.com."],
  GOOGLE_WORKSPACE_ADMIN_INVALID: ["위임받을 관리자의 이메일 주소를 입력하세요.", "Enter the address of the administrator to act as."],
  GOOGLE_WORKSPACE_KEY_INVALID: ["서비스 계정 키(JSON 파일의 내용)를 그대로 붙여 넣으세요.", "Paste the service account key (the JSON file's content) as it is."],
  GITLAB_INSTANCE_SOURCES_REQUIRED: ["인스턴스 전체 목록을 하나 이상 고르세요.", "Choose at least one instance-wide list."],
  SLACK_ORGANIZATION_ID_INVALID: ["조직 ID(E로 시작) 또는 워크스페이스 ID(T로 시작)를 입력하세요.", "Enter an organization ID (starting with E) or a workspace ID (starting with T)."],
  SLACK_ADMIN_USER_TOKEN_REQUIRED: ["봇 토큰이 아니라 조직 관리자의 사용자 토큰(xoxp-)을 입력하세요.", "Enter an organization admin's user token (xoxp-), not a bot token."],
  SLACK_ROTATING_TOKEN_NOT_SUPPORTED: ["토큰 교체가 켜진 앱의 토큰은 12시간 뒤 멈춥니다. 앱에서 한 번 켠 교체는 끌 수 없으니 마법사의 링크로 새 앱을 만드세요.", "A token of an app with token rotation stops after 12 hours. Rotation cannot be turned off once on, so make a new app from the wizard's link."],
  SLACK_TOKEN_INVALID: ["Slack 사용자 토큰(xoxp-) 형식이 아닙니다.", "That is not a Slack user token (xoxp-)."],
};

/** A refusal from the provider connection API, with the field it names in the reader's language. */
export function onboardingText(message: string, fields: FieldSpec[], L: Say): string | null {
  const code = message.split(/[\s]/, 1)[0].trim();
  const [head, arg] = code.split(":", 2);
  const known = CODES[head];
  if (known) return L(known[0], known[1]);
  const field = arg ? fields.find(item => item.name === arg) : undefined;
  const name = field ? label(field, L) : arg;
  if (/^(TARGET|PLAN|CREDENTIAL)_FIELD_REQUIRED$/.test(head)) return L(`${name}을(를) 입력하세요.`, `Enter ${name}.`);
  if (head === "FIELD_INVALID" || head === "CREDENTIAL_FIELD_INVALID") return L(`${name}의 형식이 맞지 않습니다.`, `${name} is not in the expected format.`);
  if (/^(TARGET|PLAN)_FIELD_UNKNOWN$/.test(head)) return L(`${name}은(는) 지금 고른 설정에서 쓰지 않습니다. 비워 두세요.`, `${name} does not apply to these settings. Leave it empty.`);
  if (head === "PURPOSE_ALREADY_ACTIVE") return L("이미 수집 중인 기능입니다.", "That feature is already collecting.");
  if (head === "PURPOSE_NOT_ACTIVE") return L("아직 수집하지 않는 기능입니다. 먼저 시작하세요.", "That feature is not collecting yet. Start it first.");
  if (/^[A-Z][A-Z0-9_]+_INVALID$/.test(head)) return L(`입력한 값을 확인하세요. (${head})`, `Check the value you entered. (${head})`);
  return null;
}
