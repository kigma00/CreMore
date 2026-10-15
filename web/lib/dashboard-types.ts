/* The shapes the dashboard reads back from `/api/v1`.
 *
 * Types only: no component, no helper, nothing that runs. They live apart from
 * the screens so a contributor can read what a response contains without
 * scrolling through the pages that render it, and so a screen can be moved into
 * its own module without dragging the whole contract with it.
 *
 * Each one mirrors a response the API already documents (docs/API.md). Fields
 * are optional here when the API may omit them, which is how "not collected"
 * reaches the UI as an absence rather than a zero.
 */

import type { ActionCapabilities, CredentialClassification, CredentialLifecycle } from "@/lib/credential-lifecycle";

export type Account = {
  id: string;
  account_id: string;
  name: string;
  environment?: string;
  scanner_role_arn?: string;
  remediation_role_arn?: string;
  enabled: boolean;
  validation_status: string;
  validation_detail?: string | null;
  validated_at?: string | null;
  access?: "ROLE" | "RUNTIME_IDENTITY" | "SSO_PERMISSION_SET";
  sso_role_name?: string | null;
  source?: string;
  remediation_validation_status?: string;
  remediation_validation_detail?: string | null;
  remediation_validated_at?: string | null;
  org_blocks?: string[];
  org_state?: string | null;
  discovery_context?: {
    organization?: { status: string; organization_id?: string | null; management_account_id?: string | null; parent_id?: string | null; path?: { id: string; name: string }[]; last_successful_at?: string | null; reason?: string | null };
    control_tower?: { status: string; registered_ou_id?: string | null; registered_ou_name?: string | null; account_status?: string | null; baseline_arn?: string | null; baseline_version?: string | null; drift_status?: string | null; last_successful_at?: string | null; reason?: string | null };
  };
  inventory_summary?: { status: string; last_success_at?: string | null; last_attempt_at?: string | null; schedule_minutes?: number | null; reasons?: string[] };
};
export type Scan = {
  id: string;
  status: string;
  engine_name?: string;
  engine_version?: string;
  started_at?: string;
  completed_at?: string;
  accounts_total: number;
  accounts_completed: number;
  resources_discovered: number;
  resources_scanned: number;
  resources_unchanged?: number;
  resources_skipped: number;
  resources_failed: number;
  bytes_scanned: number;
  findings_total: number | null;
  findings_count_status?: string;
  error_summary?: string;
  created_at: string;
  options?: ScanOptions;
};
export type ScanOptions = {
  scan_versions?: boolean;
  scan_archives?: boolean;
  full_scan?: boolean;
  max_object_size_mb?: number;
  max_age_days?: number;
  bucket_globs?: string[];
  exclude_bucket_globs?: string[];
  exclude_key_globs?: string[];
  exclude_prefixes?: string[];
  exclude_suffixes?: string[];
};
export type Finding = {
  id: string;
  severity: string;
  workflow_status: string;
  all_locations_removed?: boolean | null;
  credential_id: string;
  credential_type: string;
  credential_class?: string;
  provider?: string;
  providers: string[];
  identifier_hint?: string;
  credential_status: string;
  principal_name?: string;
  business_owner?: string;
  team?: string;
  ownership?: CredentialOwnership;
  owner_review?: OwnerReview;
  credential_metadata?: CredentialMetadata;
  governance?: CredentialGovernance;
  last_used_at?: string;
  account_id?: string;
  account_name?: string;
  environment?: string;
  scope_id: string;
  scope_name: string;
  scope_type: string;
  source_connection_id?: string;
  source_type: string;
  resource_name: string;
  location: string;
  exposure_count: number;
  first_seen_at: string;
  last_seen_at: string;
};
export type CredentialOwnership = {
  principal: {
    status: "UNKNOWN" | "OBSERVED" | "RECORDED" | "CONFLICT";
    name?: string;
    id?: string;
    kind?: string;
    basis: string;
    evidence_at?: string;
  };
  response_owner?: string;
  response_team?: string;
  source_namespace?: string;
  source_basis?: "github_repository_url";
};
export type TimeEvidence = { at: string; source: string; observed_at?: string };
export type CredentialVariant = "github.pat.classic" | "github.pat.fine_grained" | "github.app.installation_token" | "github.app.user_access_token" | "github.oauth.access_token" | "github.refresh_token";
export type MetadataFieldStatus = "NO_INFORMATION" | "INVALID" | "NOT_PROBED" | "AVAILABLE" | "NOT_APPLICABLE" | "NOT_SUPPORTED" | "NOT_RECORDED" | "NOT_OBSERVED" | "COLLECTION_LIMITED" | "ACCESS_DENIED" | "COLLECTION_FAILED" | "INVALID_METADATA" | "NOT_COLLECTED" | "NOT_VERIFIABLE" | "NOT_IMPLEMENTED" | "CONTEXT_ONLY" | "NOT_RETURNED" | "NOT_EXPOSED_BY_PROVIDER" | "PLAN_OR_VERSION_REQUIRED" | "OUTSIDE_RETENTION" | "LOGGING_NOT_ENABLED" | "STALE_OR_CONFLICTING" | "EXACT_CREDENTIAL_MATCH_REQUIRED";
export type MetadataFieldStatuses = Partial<Record<string, MetadataFieldStatus>>;
export type CredentialMetadata = {
  credential_variant?: CredentialVariant;
  classification?: CredentialClassification;
  lifecycle?: CredentialLifecycle;
  action_capabilities?: ActionCapabilities;
  field_status?: MetadataFieldStatuses;
  created_at?: TimeEvidence;
  issued_at?: TimeEvidence;
  expires_at?: TimeEvidence;
  expiry_status: string;
  principal_name?: string;
  principal_id?: string;
  principal_kind?: string;
  principal_observed_at?: string;
  principal_arn?: string;
  principal_source?: string;
  issuer_arn?: string;
  session_issuer_arn?: string;
  source_identity?: string;
  provider_status?: string;
  provider_status_observed_at?: string;
  last_used_at?: TimeEvidence;
  last_used_service?: string;
  last_used_region?: string;
  last_observed_use_at?: TimeEvidence;
  scopes: string[];
  scope_source?: string;
  scope_observed_at?: string;
  capabilities?: { name: string; status: string; count?: number }[];
  capability_source?: string;
  capability_observed_at?: string;
  verification_host?: string;
  potential_access?: CredentialPotentialAccess;
  identity_policies?: CredentialIdentityPolicies;
  audit_evidence?: {
    source: "GITHUB_ORG_AUDIT_LOG"; match_basis: "EXACT_TOKEN_HASH" | "UNAVAILABLE"; coverage: "OBSERVED_EVENTS_ONLY" | "SOURCE_COVERAGE_ONLY"; truncated: boolean;
    collection_status: "NOT_COLLECTED" | "PARTIAL" | "COMPLETE";
    source_coverage: { source_connection_id: string; organization?: string; observed_at?: string; complete: boolean; truncated: boolean; error_code?: string }[];
    events: { organization: string; source_connection_id: string; event_id: string; event_at: string; observed_at: string; action: string; actor?: string; actor_id?: number; programmatic_access_type?: string; scopes_at_event?: string[] | null; repository?: string; outcome: "NOT_ESTABLISHED" }[];
  };
  limitations: string[];
};
export type OwnerReview = {
  status: "OPEN" | "IN_PROGRESS" | "WAITING_OWNER" | "CLOSED";
  assigned_team?: string;
  due_at?: string;
  closed_reason?: "" | "RESPONSIBLE_TEAM_CONFIRMED" | "CREDENTIAL_RETIRED" | "NOT_ACTIONABLE";
  revision: number;
  updated_at?: string;
};
export type OwnerReviewContext = {
  status: "OBSERVED" | "NO_CODEOWNERS" | "NOT_COLLECTED" | "UNAVAILABLE" | "NOT_FOUND_OR_NOT_VISIBLE" | "TRUNCATED" | "UNSUPPORTED";
  repository?: string;
  observed_at?: string;
  inventory_connection_id?: string;
  codeowners_path?: string;
  candidates: { owner: string; kind: "TEAM" | "USER"; line: number }[];
  basis: "CODEOWNERS_DECLARATION";
  file_match: false;
  unsupported_declarations?: boolean;
  inventory_complete?: boolean;
};
export type OwnershipReviewResponse = { finding_id: string; review: OwnerReview; context: OwnerReviewContext };
export type Rule = {
  id?: string;
  name: string;
  description?: string;
  enabled: boolean;
  rule_type: string;
  keywords: string[];
  pattern: string;
  severity: string;
  revision: number;
  scope_accounts?: string[];
  scope_sources?: string[];
  include_globs?: string[];
  exclude_globs?: string[];
  exclude_words?: string[];
  provider_candidates?: string[];
  content_kinds?: string[];
  responsible_team_candidate?: string;
  fixture_tests?: { id: string; expected: boolean }[];
  exception_reason?: string;
  review_due_at?: string;
};
export type CustomRuleEvidence = { name: string; revision: number; default_severity?: string; provider_candidates?: string[]; responsible_team_candidate?: string; review_due_at?: string };
export type Exposure = {
  id: string;
  provider: string;
  scope_id: string;
  scope_name: string;
  aws_account_id?: string;
  source_connection_id?: string;
  source_type: string;
  resource_arn?: string;
  resource_name: string;
  location: string;
  region?: string;
  object_version?: string | null;
  line_number?: number | null;
  redacted_line?: string | null;
  source_location?: SourceLocation;
  severity: string;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  removed_at?: string | null;
  fp_profile_id?: string | null;
  fp_similarity?: number | null;
  detection_details?: {
    custom_rule?: CustomRuleEvidence;
    decoder_type?: string;
    fp_signal?: "WORDLIST" | "LOW_ENTROPY";
    location_basis?: string;
    decoded_line_number?: number;
    risk_score?: number;
    risk_level?: string;
    risk_confidence?: "high" | "medium" | "low";
    risk_evidence?: string[];
    risk_missing_evidence?: string[];
    risk_overrides?: string[];
    risk_policy?: string;
    risk_comparison?: RiskComparison;
    risk_confidence_reasons?: string[];
    effective_severity?: string;
    severity_basis?: "risk_model" | "custom_rule" | "policy_override" | "legacy";
    verification_state?:
      | "verified"
      | "rejected"
      | "indeterminate"
      | "restricted"
      | "unsupported"
      | "disabled";
    // Facts the issuer returned about the credential itself. These are filled
    // the same way for every provider, because the credential is the subject
    // and the platform it was found on is only where it turned up.
    verification_owner_kind?: string;
    credential_variant?: CredentialVariant;
    verification_checked_at?: string;
    verification_owner_name?: string;
    verification_owner_id?: string;
    verification_context_owner_kind?: string;
    verification_context_owner_id?: string;
    verification_context_owner_name?: string;
    verification_workspace?: string;
    verification_scopes?: string[] | string;
    verification_expires_at?: string;
    aws_account_id?: string;
    aws_resource_type?: string;
    aws_canary?: boolean;
    exposure?: "public" | "public_inherited" | "internal" | "unknown";
  };
};
export type Audit = {
  id: string;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  target_name?: string | null;
  note?: string | null;
  from_status?: string | null;
  to_status?: string | null;
  recovered_from_connection?: boolean;
  created_at: string;
};
export type CredentialUsageResource = {
  type?: string;
  name?: string;
};
export type CredentialUsageEvent = {
  event_id: string;
  event_time: string;
  region: string;
  evidence_source: "EVENT_HISTORY" | "CLOUDTRAIL_LAKE" | "SCANNER_MARKER_OBSERVED" | "SCANNER_VERIFICATION" | "CONFIRMED_VERIFICATION_EVENT";
  event_category: "MANAGEMENT" | "DATA" | "UNKNOWN";
  event_source: string;
  event_name: string;
  access_mode: "READ" | "WRITE" | "UNKNOWN";
  outcome: "SUCCEEDED" | "DENIED" | "UNKNOWN";
  error_code?: string;
  source_address?: string;
  source_address_kind?: "IPV4" | "IPV6" | "HOSTNAME" | "AWS_INTERNAL";
  principal_arn?: string;
  principal_name?: string;
  session_issuer_arn?: string;
  source_identity?: string;
  workload_identity?: string;
  session_created_at?: string;
  resources: CredentialUsageResource[];
  // The technique this call belongs to, added when the snapshot is read. Absent
  // means unclassified, which ordinary traffic mostly is.
  technique_id?: string;
};
export type ObservedCallTechniques = {
  revision: string;
  observed: { technique_id: string; technique_name: string; events: number }[];
  classified_events: number;
  total_events: number;
};
export type CredentialUsageCoverage = {
  region: string;
  status: "COMPLETE" | "CAPPED" | "PARTIAL" | "FAILED" | "PENDING";
  event_scope: string;
  evidence_source: "EVENT_HISTORY";
  events_collected: number;
  error_code?: string;
  window_start: string;
  window_end: string;
  collected_at: string;
};
export type CloudTrailLakeCoverage = {
  configured: boolean;
  status: "NOT_CONFIGURED" | "COMPLETE" | "CAPPED" | "FAILED";
  region?: string;
  event_scope: "MANAGEMENT_AND_DATA";
  evidence_source: "CLOUDTRAIL_LAKE";
  events_collected: number;
  error_code?: string;
  window_start?: string;
  window_end?: string;
  collected_at?: string;
};
export type CredentialPotentialAction = {
  action: string;
  service: string;
  decision: "ALLOWED" | "EXPLICIT_DENY" | "IMPLICIT_DENY";
  risk: string;
  missing_context_values: string[];
  organizations_allowed?: boolean;
  permissions_boundary_allowed?: boolean;
  // NAMED (assessment v3): allowed only on these ARNs, which the principal's own Allow statements name.
  resource_scope?: "ALL" | "NAMED";
  resources?: string[];
};
// One ARN the principal's Allow statements name, simulated for the actions `*` did not allow (assessment v3).
export type CredentialNamedResource = {
  resource: string; actions: string[]; allowed: string[]; explicit_deny: string[]; missing_context_values: string[];
  resource_policy: "EVALUATED" | "NONE" | "NOT_READ" | "NOT_SUPPORTED";
  // A KMS key's: actions an identity policy allows that its key policy neither delegates to IAM policies nor grants
  // the user or everyone directly.
  key_policy_blocks?: string[];
  // Actions with no answer because a condition needs request context (keys: missing_context_values, per resource).
  conditional?: string[];
};
export type IdentityPolicyStatement = { sid: string; effect: "Allow" | "Deny"; actions: string[]; not_actions: string[]; resources: string[]; not_resources: string[]; condition_keys: string[]; truncated: boolean };
export type IdentityPolicy = { source: string; name: string; arn?: string; aws_managed?: boolean; group?: string; statements: IdentityPolicyStatement[] };
export type CredentialIdentityPolicies = {
  collection_status: string;
  principal_arn: string;
  principal_type: string;
  collected_at?: string;
  policies: IdentityPolicy[];
  errors: { step: string; error_code: string }[];
  statements_truncated?: boolean;
  summary?: { quarantine_policies?: string[]; deny_all_policies: string[]; allow_all_policies: string[]; permissions_boundary: boolean; boundary_limits_allow_all: boolean; allow_statements: number; deny_statements: number; conditional_statements: number; allowed_actions: string[]; allowed_actions_truncated: boolean };
};
export type CredentialPotentialAccess = {
  assessment_version?: number;
  effective_access?: "NOT_EVALUATED";
  resource_arns?: string[];
  request_context?: "NOT_SUPPLIED";
  assessment_status?: "MISSING_CONTEXT" | "SIMULATION_ONLY";
  // PARTIAL: some actions were decided before an error (investigation/potential_access.py).
  collection_status: "NOT_COLLECTED" | "NOT_CONFIGURED" | "COMPLETE" | "PARTIAL" | "FAILED" | "UNSUPPORTED";
  evidence_level: "POTENTIAL";
  method: "IAM_SIMULATE_PRINCIPAL_POLICY";
  scope: "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_RESOURCES" | "CURATED_HIGH_IMPACT_ACTIONS_ON_ALL_AND_NAMED_RESOURCES";
  named_resources?: CredentialNamedResource[];
  named_resources_complete?: boolean;
  principal_arn?: string;
  // For a temporary STS session, the role it assumed that was actually simulated.
  evaluated_role_arn?: string;
  evaluated_at?: string;
  error_code?: string;
  limitations: string[];
  actions: CredentialPotentialAction[];
};
export type CredentialScenarioNode = {
  id: string;
  kind: "EXPOSURE" | "CREDENTIAL" | "IDENTITY" | "SESSION" | "WORKLOAD" | "ACTION" | "RESOURCE";
  provider?: string;
  label: string;
  detail?: string;
  account_id?: string;
  region?: string;
  resource_type?: string;
  resource_name?: string;
  location?: string;
  resource_ref?: string;
};
export type CredentialScenarioEdge = {
  from: string;
  to: string;
  relationship: string;
  evidence_level: "OBSERVED" | "INFERRED";
  evidence_source: string;
  event_count: number;
  first_observed_at?: string;
  last_observed_at?: string;
};
export type CredentialScenario = {
  id: string;
  provider: string;
  title: string;
  summary: string;
  primary: boolean;
  evidence_level: "OBSERVED" | "INFERRED";
  impact: "WRITE_OBSERVED" | "READ_OBSERVED" | "ATTEMPT_ONLY" | "ACTIVITY_OBSERVED";
  first_observed_at: string;
  last_observed_at: string;
  event_count: number;
  read_count: number;
  write_count: number;
  denied_count: number;
  service_count: number;
  resource_count: number;
  nodes: CredentialScenarioNode[];
  edges: CredentialScenarioEdge[];
};
export type CredentialUsage = {
  credential_class: "LONG_LIVED" | "TEMPORARY_STS" | "UNKNOWN";
  collection_status: "NOT_COLLECTED" | "COMPLETE" | "PARTIAL" | "FAILED" | "ACCOUNT_UNVERIFIED";
  recorded_collection_status?: string;
  collected_account_id?: string | null;
  collected_via?: string;
  region_discovery_status?: "COMPLETE" | "FALLBACK";
  region_discovery_error?: string;
  event_scope: "MANAGEMENT" | "MANAGEMENT_AND_DATA";
  window_start?: string;
  window_end?: string;
  collected_at?: string;
  last_used?: {
    status: "AVAILABLE" | "NO_INFORMATION" | "DENIED" | "FAILED" | "NOT_REQUESTED";
    observed_at: string;
    error_code?: string;
    at?: string;
    service?: string;
    region?: string;
  };
  regions_discovered: number;
  regions_complete: number;
  regions_failed: number;
  regions_capped: number;
  events_per_region?: number;
  requests_used?: number;
  request_limit?: number;
  refresh_job?: { id: string; status: string; error_code?: string | null };
  summary?: { events: number; denied: number;
    services: Record<string, { service: string; calls: number; writes: number; denied: number; last: string | null }>;
    techniques: Record<string, number> };
  events: CredentialUsageEvent[];
  coverage: CredentialUsageCoverage[];
  scenarios: CredentialScenario[];
  cloudtrail_lake: CloudTrailLakeCoverage;
  potential_access: CredentialPotentialAccess;
  techniques?: ObservedCallTechniques;
};

export type SourceLocation = {
  provider_instance_id?: string; source_api_version?: string; source_server_version?: string; source_deployment?: string;
  source_provider: string; coordinate_basis: "EXACT_ORIGINAL" | "EXTRACTED_TEXT" | "UNCONFIRMED";
  revision?: string; revision_kind?: string; line_start?: number; line_end?: number; extracted_line_start?: number;
  page_id?: string; block_id?: string; block_path?: string; observed_modified_at?: string;
  transform_chain?: string[]; context_status: string;
  original_link: { status: "AVAILABLE" | "CURRENT_ONLY" | "UNAVAILABLE"; url?: string; reason_code?: string; requires_source_auth: boolean; historical_content: boolean };
};
export type RiskComparison = {
  policy_version: string; mode: string; assessment_id: string; evaluated_at: string; status: string;
  risk_score: number | null; minimum: number | null; maximum: number | null; evidence_coverage: number;
  response_priority: string; residual_investigation: string; incident_disposition: string; missing_evidence: string[];
  contributions: { dimension: string; weight: number; minimum: number; maximum: number; representative: number; points: number; evidence_satisfied: boolean; reason: string }[];
};

export type GovernanceFact = { key: string; value: unknown; source?: string; source_detail?: string; confidence: number | null; confidence_basis: string; observed_at: string | null; availability: string; reason: string };
type DocumentedCapability = { documented_support: string; reason: string };
type AssessmentAxis = { status: string; reasons: string[] };
export type GovernanceAssessment = { exposure_risk: AssessmentAxis; management_quality: AssessmentAxis; observation_limits: AssessmentAxis };
export type CredentialGovernance = {
  revision: string; credential_id: string; credential_type: string; semantic_type_id?: string; classification_status: string; classification_basis: string; provider: string;
  metadata: GovernanceFact[]; management: { status: string; match_status: string; match_basis?: string; reason: string };
  type_capability: { credential_type: string; provider: string; execution_authorized: boolean; connection_required: boolean; supports_verification: DocumentedCapability; supports_expiration: DocumentedCapability; supports_last_used: DocumentedCapability; supports_provider_owner: DocumentedCapability; supports_last_actor: DocumentedCapability; supports_disable: DocumentedCapability; supports_revoke: DocumentedCapability; supports_rotation: DocumentedCapability; supports_refresh: DocumentedCapability };
  panel_hints: string[]; discovery_coverage: string; limitations: string[];
  assessment?: GovernanceAssessment;
};
