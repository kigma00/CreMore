/* The credential list the API serves (GET /api/v1/credential-records) and what the screens
 * derive from one row. */

import type { Risk, Status, Verify } from "@/console/ui";
import type { CredentialIdentityPolicies, CredentialPotentialAccess } from "@/lib/dashboard-types";
import { DAY, time } from "@/console/text";

export type Kind = "token" | "apikey" | "cloud" | "other";
export type Visibility = "public" | "org" | "internal" | "private" | "unknown";
export type StepState = "open" | "progress" | "done" | "na";
export type StepId = "revoke" | "cleanup" | "vault" | "scope";

export type Exposure = {
  source_type: string; resource_name: string; location: string; line: number | null; snippet: string | null;
  visibility: Visibility; current: boolean; first_seen_at: string | null; last_seen_at: string | null;
  removal_pending?: boolean;
  /** Who last changed the file, as its code host said. */
  author?: string | null;
};

export type Contact = { channel: "mail" | "slack"; template: "info" | "revoke" | "purpose" | "scope"; recipients: number; due_at: string; at: string; by: string };

export type ResponseState = "NEW" | "REVIEWING" | "ASSIGNED" | "SENDING" | "SEND_UNKNOWN" | "NOT_SENT" | "WAITING_OWNER" | "REPORT_REQUIRED" | "WAITING_VERIFICATION" | "NEEDS_ACTION" | "REMOVED" | "COMPLETED";
/** How a response request reaches its person (ResponseTicketBody.channel in cremore/api/routes/credentials.py). */
export type ResponseChannel = "slack" | "mail" | "record" | "ticket";
export type ResponseReport = {
  id: string; version: number; hash: string; by: string; received_at: string; basis: string;
  result: "DONE" | "INCOMPLETE" | "EXCEPTION"; path: "RETIRED" | "REPLACED" | "EXCEPTION";
  actions: string[]; explanation: string; performed_at: string; replacement_plan_id?: string; replacement_entity_id?: string;
};
export type ResponseCheck = { state: "PASS" | "WAIT" | "NA"; reason: string; at?: string; run_id?: string; plan_id?: string; reference?: string; entity_id?: string };
export type ResponseCycle = {
  request_id: string; cycle: number; state: ResponseState; requested_by: string; requested_at: string;
  requested_by_name?: string | null; requested_by_email?: string | null;
  ticket_opened_at?: string | null;
  channel?: ResponseChannel; link_expires_at?: string | null; link_expired?: boolean;
  /** The team channel post whose thread carries progress (phase 2), and why it could not be posted or updated. */
  thread?: { channel_id: string; name: string } | null; thread_error?: string | null;
  assigned_to: string; ticket?: { system: string; ticket: string; approval: string; approver: string; url?: string | null } | null;
  recipient?: { id: string; person_ref: string; name: string; email: string; department?: string | null; title?: string | null; state: string } | null;
  team?: string | null; mapping_basis?: string; mapping_checked_at?: string;
  answered_at?: string | null; received_at?: string | null; answered_by?: string | null; verified_at?: string | null;
  last_scan_at?: string | null; last_scan_id?: string | null; error_code?: string | null;
  completion_version?: number; answer?: string; report?: ResponseReport | null; report_count?: number;
  completed_at?: string | null; verification?: Record<string, ResponseCheck> | null;
  recurred_at?: string | null;
};
export type ResponseSummary = { state: ResponseState; version: number; current: ResponseCycle | null; history?: ResponseCycle[]; history_total?: number; history_offset?: number; can_report?: boolean; can_request?: boolean; reviewed_at?: string | null; reviewed_by?: string | null };

export type IAMPolicySummary = {
  status: "COMPLETE" | "PARTIAL" | "DENIED" | "FAILED"; checked_at: string;
  policy_names: string[]; allow_actions: string[]; deny_statements: number; conditional_statements: number;
  permissions_boundary: boolean; truncated: boolean; reason: string | null;
};

export type CredentialRecord = {
  id: string; credential_id: string | null; finding_id: string | null; entity_id: string | null;
  provider: string; credential_type: string; category: string; kind: Kind; name: string | null; hint: string | null;
  exposed: boolean; status: Status | null; workflow_status: string | null; risk: Risk;
  exposure_state?: "ACTIVE" | "REMOVED" | null; all_locations_removed?: boolean;
  active_location_count?: number; removed_location_count?: number; removal_pending_location_count?: number;
  response?: ResponseSummary | null;
  acknowledged_at: string | null; resolved_at: string | null;
  verification: { state: Verify; at: string | null; basis: string | null; reason: string | null };
  owner: { name: string | null; team: string | null; basis: string; where?: string; person_ref?: string; email?: string | null;
    department?: string | null; title?: string | null; state?: string } | null;
  /** How many people can read the first exposed repository, as its code host listed them. */
  access?: { count: number; truncated: boolean; basis: string | null; repository: string | null; collected_at: string | null } | null;
  issuer: { name: string; role: string | null; basis: string } | null;
  exposures: Exposure[]; exposure_count: number; location_count: number;
  first_seen_at: string | null; last_seen_at: string | null;
  created_at: string | null; expires_at: string | null; expiry: "date" | "none" | "unknown";
  last_used: { at: string; basis: string } | null;
  scopes: { name: string; write: boolean | null }[] | null;
  aws_permissions?: { identity_policies?: CredentialIdentityPolicies; potential_access?: CredentialPotentialAccess } | null;
  /** Distinct addresses the saved usage lookup saw this key used from, newest first, up to 5 (empty unless it ran in the key's own account). */
  recent_sources?: SourceAddress[];
  /** How many distinct addresses that lookup saw across every event it read; a lower bound when `recent_sources_more`. */
  recent_sources_total?: number;
  recent_sources_more?: boolean;
  vault: { state: "stored" | "none" | "unknown"; where: { provider: string; connection: string; reference: string }[]; basis: string; reasons: string[]; absence_basis: string | null };
  tags: string[]; stage: "review" | "action" | null;
  steps: Partial<Record<StepId, { status: StepState; comment: string; updated_by: string; updated_at: string }>>;
  contact: Contact | null; annotations_revision: number;
  review: { status: "OPEN" | "IN_PROGRESS" | "WAITING_OWNER" | "CLOSED"; assigned_team: string | null; due_at: string | null; closed_reason: string; revision: number; updated_at: string | null } | null;
  issued: { entity_id: string | null; provider: string; origin: string; tenant: string; object_id: string; type?: string | null; observed_at: string | null;
    current?: boolean; last_used_status?: string; iam_policies?: IAMPolicySummary | null;
    creator?: { arn: string; at: string; event_id: string; region: string; source: string; current: boolean; run_id: string } | null;
    creator_status?: string; creator_name?: string | null } | null;
};

export type SourceAddress = { address: string; kind: "IPV4" | "IPV6" | "HOSTNAME" | "AWS_INTERNAL"; last_seen_at: string | null; count: number };

/** An address a key was used from; CloudTrail names an AWS service call by the service's host, which is not an IP address. */
export const sourceLabel = (address: string, kind: string | undefined, L: (ko: string, en: string) => string) =>
  kind === "AWS_INTERNAL" ? L(`AWS 서비스 ${address}`, `AWS service ${address}`) : address;

export function creatorLabel(c: CredentialRecord, L: (ko: string, en: string) => string): string | null {
  if (c.issued?.provider !== "aws_iam") return null;
  const creator = c.issued.creator;
  if (creator) {
    const resource = creator.arn.replace(/^arn:[^:]+:(?:iam|sts)::\d{12}:/, "");
    const name = resource.startsWith("user/") ? resource.split("/").pop() || resource : resource === "root" ? L("루트 계정", "Root account") : resource;
    return `${creator.current ? "" : L("과거 수집 근거: ", "Historical evidence: ")}${name}`;
  }
  switch (c.issued.creator_status) {
    case "RUNNING": return L("CloudTrail 수집 중", "CloudTrail collection running");
    case "CONFLICT": return L("CloudTrail 생성자 근거가 충돌함", "Conflicting CloudTrail creator evidence");
    case "INCOMPLETE": return L("CloudTrail 조회 미완료·권한 또는 수집 상태 확인 필요", "CloudTrail lookup incomplete; check permissions and collection status");
    case "NOT_OBSERVED_IN_WINDOW": return L("조회한 리전·기간에서 생성자를 확인하지 못함", "Creator not confirmed in the queried regions and time window");
    case "NOT_COLLECTED": return L("CloudTrail 연결됨 · 아직 미수집", "CloudTrail connected; not collected yet");
    default: return L("CloudTrail 미연결", "CloudTrail not connected");
  }
}

export function lastUseGap(c: CredentialRecord, L: (ko: string, en: string) => string): string | null {
  if (c.issued?.provider !== "aws_iam") return null;
  switch (c.issued.last_used_status) {
    case "NO_INFORMATION": return L("사용 기록 없음 (IAM 조회)", "No usage record (IAM lookup)");
    case "DENIED": return L("마지막 사용 조회 권한 부족", "Last-use lookup denied");
    case "FAILED": return L("마지막 사용 조회 실패", "Last-use lookup failed");
    case "NOT_REQUESTED": case "NOT_COLLECTED": return L("마지막 사용을 수집하지 않음", "Last use not collected");
    default: return null;
  }
}

export function iamPolicyLabel(c: CredentialRecord, L: (ko: string, en: string) => string): string {
  const p = c.issued?.iam_policies;
  if (!p) return L("IAM 정책 미수집", "IAM policies not collected");
  let label = p.status === "DENIED" ? L("IAM 정책 조회 권한 부족", "IAM policy lookup denied")
    : p.status === "FAILED" ? L("IAM 정책 조회 실패", "IAM policy lookup failed")
    : p.policy_names.length ? L(`IAM 정책 ${p.policy_names.length}개`, `${p.policy_names.length} IAM ${p.policy_names.length === 1 ? "policy" : "policies"}`)
    : p.status === "COMPLETE" ? L("연결된 IAM 정책 없음", "No attached IAM policies")
    : L("IAM 정책 조회 일부 실패", "IAM policy lookup partly failed");
  if (p.status === "PARTIAL" && p.policy_names.length) label += L(" · 일부 조회", " · Partial lookup");
  if (p.truncated) label += L(" · 표시 한도 적용", " · Display limit reached");
  return c.issued?.current === false ? L("과거 관측: ", "Historical observation: ") + label : label;
}

export type Coverage = {
  exposed: number; matched: number; no_vault_match: number; unknown: number; issuance_only: number; vault_only: number;
  managed: number; issued: number; issued_in_vault: number; issued_not_in_vault: number; issued_unknown: number;
  matched_percent: number | null; complete: boolean;
};

export type RecordsResponse = {
  items: CredentialRecord[]; total: number; complete: boolean; scope_confirmed: boolean; scope_reasons: string[];
  coverage: Coverage; generated_at: string;
};

export const RECORDS_PATH = "credential-records";

// Removal requires the server's complete reconciliation, never an empty/partial location list.
export const isRemoved = (c: CredentialRecord) => c.exposed && (c.exposure_state === "REMOVED" || c.all_locations_removed === true);
export const isExposed = (c: CredentialRecord) => c.exposed && !isRemoved(c);
export const recordStatus = (c: CredentialRecord): Status | null => {
  if (c.status === "fp" || c.status === "ignored" || !c.response) return c.status;
  return c.response.state === "COMPLETED" ? "done" : c.response.state === "NEW" ? "pending" : ["ASSIGNED", "REVIEWING"].includes(c.response.state) ? "review" : "action";
};
export const isOpen = (c: CredentialRecord) => isExposed(c) && !["done", "fp", "ignored"].includes(recordStatus(c) ?? "");
export const countable = (c: CredentialRecord) => isExposed(c) && c.status !== "fp";
export const revoked = (c: CredentialRecord) => c.verification.state === "revoked";
export const ended = (c: CredentialRecord) => ["revoked", "inactive", "expired"].includes(c.verification.state);
export const hasWrite = (c: CredentialRecord) => Boolean(c.scopes?.some(scope => scope.write));

/** IAM policy evidence is separate from token scopes and from effective access. */
export function awsPermissionEvidence(c: CredentialRecord) {
  const lookup = c.aws_permissions?.identity_policies;
  const inventory = c.issued?.provider === "aws_iam" ? c.issued.iam_policies : null;
  const read = (status?: string) => status === "COMPLETE" || status === "PARTIAL";
  const fromInventory = Boolean(read(inventory?.status) && (!read(lookup?.collection_status)
    || (time(inventory?.checked_at) ?? 0) > (time(lookup?.collected_at) ?? 0)));
  const policyObserved = fromInventory || read(lookup?.collection_status);
  const policies = fromInventory ? inventory!.policy_names : read(lookup?.collection_status) ? lookup!.policies.map(p => p.name) : [];
  const potential = c.aws_permissions?.potential_access;
  const simulationObserved = read(potential?.collection_status);
  const actions = simulationObserved ? potential!.actions.filter(a => a.decision === "ALLOWED"
    && !a.missing_context_values?.length && a.organizations_allowed !== false && a.permissions_boundary_allowed !== false) : [];
  return { policies, policyObserved, fromInventory, simulationObserved, actions,
    broadPolicy: Boolean(fromInventory ? inventory?.allow_actions?.includes("*") : lookup?.summary?.allow_all_policies?.length),
    historical: fromInventory && c.issued?.current === false,
    partial: (fromInventory ? inventory?.status : lookup?.collection_status) === "PARTIAL"
      || potential?.collection_status === "PARTIAL" };
}
export const noExpiry = (c: CredentialRecord) => c.expiry === "none" && !ended(c) && c.status !== "fp";
export function daysTo(value: string | null, now = Date.now()) {
  const at = time(value);
  return at === null ? null : Math.ceil((at - now) / DAY);
}
export const expSoon = (c: CredentialRecord, now = Date.now()) => {
  const days = daysTo(c.expires_at, now);
  return days !== null && days >= 0 && days <= 30 && !ended(c);
};
export const expired = (c: CredentialRecord, now = Date.now()) => {
  const days = daysTo(c.expires_at, now);
  return days !== null && days < 0;
};
export const stale = (c: CredentialRecord, now = Date.now()) => {
  const at = time(c.last_used?.at);
  return at !== null && now - at > 90 * DAY && !ended(c);
};
export const ownerless = (c: CredentialRecord) => !c.owner?.name && !c.owner?.team;
export const VIS_ORDER: Visibility[] = ["public", "org", "internal", "private"];
export function worstVis(c: CredentialRecord): Visibility | null {
  for (const level of VIS_ORDER) if (c.exposures.some(e => e.current && e.visibility === level)) return level;
  return null;
}
export function overdue(c: CredentialRecord, now = Date.now()) {
  if (!c.contact || !isOpen(c)) return false;
  const due = time(`${c.contact.due_at}T23:59:59`);
  return due !== null && due < now;
}

/** A readable name: the issuer's name for the credential, else its type and masked hint. */
export function recordName(c: CredentialRecord, typeName: string) {
  return c.name || typeName;
}

// Where an exposure was found, by the provider the dashboard shows for that source.
const SOURCE_PROVIDER: Record<string, string> = { s3: "s3", gcp: "gcs", azure_blob: "azure", azure_devops: "azure_devops" };
export function exposureService(sourceType: string) {
  return SOURCE_PROVIDER[sourceType] ?? sourceType;
}
