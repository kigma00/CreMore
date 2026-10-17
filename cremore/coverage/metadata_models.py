"""Schema 2: bounded provider metadata, never arbitrary provider responses.

Schema 1 remains in models.py. Provider status is an observation, not a
credential-verification result. Missing/null/invalid fields retain their shape
without storing the rejected value. Checkpoints are private worker state.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    TypeAdapter,
    field_validator,
    model_validator,
)

from cremore.coverage.models import MAX_BATCH, SCHEME, Code, Digest, StrictModel, digest
from cremore.task_state import safe_task_state

Provider = Literal["github", "github_identity", "notion", "slack"]
Purpose = Literal["issuer_inventory", "vault_metadata", "usage", "identity_status"]
Capability = Literal["inventory", "audit", "relations", "vault_metadata", "issuer_digest", "policy", "public_keys", "identity_status"]
IdentityKeyKind = Literal["IDP_USER_ID", "LOGIN", "EMAIL", "SCIM_EXTERNAL_ID", "SAML_NAME_ID", "EXTERNAL_UID", "IDP_OBJECT_ID", "VERIFIED_EMAIL", "UNVERIFIED_EMAIL", "PROVIDER_LOGIN"]
FingerprintScheme = Literal["cremore-credential-fingerprint-v1/hmac-sha256", "github-token-sha256/hmac-sha256-v1"]
ObjectKind = Literal["credential", "principal", "installation", "policy", "request", "context", "public_key", "trust", "vault_item", "vault_version", "runner", "resource", "unknown"]
SafeText = Annotated[str, Field(max_length=2048)]
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET = re.compile(r"(?:gh[pousr]_|github_pat_|glpat-|ntn_|(?<![A-Za-z0-9_])(?:adm_|secret_)[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[baprsceod]-|xapp-|xwfp-|xoxe\.|hooks\.slack\.com/services/|-----BEGIN [^-]*PRIVATE KEY|(?i:bearer )[A-Za-z0-9])")


def metadata_text(value: str) -> str:
    if len(value) > 2048 or _CONTROL.search(value) or _SECRET.search(value):
        raise ValueError("UNSAFE_METADATA")
    return value


def canonical_origin(value: str) -> str:
    # Pure validator; the source_config compatibility module would load the content registry.
    from cremore.sources.validation import https_base

    https_base(value)
    metadata_text(value)
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("INVALID_PROVIDER_ORIGIN") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or "%" in parsed.netloc
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("HTTPS_ORIGIN_REQUIRED")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = "[" + host + "]"
    return "https://" + host + (f":{port}" if port and port != 443 else "")


def timestamp(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("TIMEZONE_REQUIRED")
    return parsed.astimezone(UTC).isoformat()


class MetadataModel(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, revalidate_instances="always")


class MetadataScope(MetadataModel):
    kind: Literal["organization", "enterprise", "group", "project", "folder", "workspace", "subscription", "vault", "account", "repository", "user", "installation", "namespace", "realm"]
    id: str = Field(min_length=1, max_length=512)

    _id = field_validator("id")(metadata_text)


class MetadataOptions(MetadataModel):
    mode: Literal["inventory", "organization", "enterprise"] = "inventory"
    sources: list[str] = Field(default_factory=list, max_length=100)
    api_path: str = Field(default="", max_length=512, pattern=r"^(?:/[A-Za-z0-9_-]+)*$")
    include_provider_hashes: bool = False
    # IdP collections: keep each person's display name, email, department and title as facts, for owner,
    # contact and access views. Matching (the departed-owner check) still uses keyed digests only.
    keep_profiles: bool = False
    include_audit_events: bool = False
    audit_created_after: str | None = None
    audit_lookback_days: int | None = Field(default=None, ge=1, le=36500)
    locations: list[str] = Field(default_factory=list, max_length=100)
    include_deleted: bool = False
    include_actions: bool = False
    # GitHub only: Actions runs over their own window (None keeps the audit
    # window), which audit logs to read, an Enterprise read without its
    # organizations, and a wall-clock limit for one run (waits included).
    actions_run_days: int | None = Field(default=None, ge=1, le=365)
    audit_scope: Literal["both", "enterprise", "organization"] = "both"
    enterprise_only: bool = False
    github_inventory: bool = True
    # At most 5 hours: a run must finish within the store's 6-hour run lifetime.
    run_time_limit_minutes: int | None = Field(default=None, ge=1, le=300)
    max_targets: int = Field(default=50, ge=1, le=500)
    page_size: int = Field(default=100, ge=1, le=1000)
    requests_per_second: float = Field(default=2.0, gt=0, le=100)
    burst: int = Field(default=2, ge=1, le=100)
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    max_retries: int = Field(default=4, ge=0, le=10)
    max_consecutive_rate_limits: int = Field(default=3, ge=1, le=100)
    retry_min_seconds: float = Field(default=1.0, gt=0, le=60)
    max_response_bytes: int = Field(default=1048576, ge=1024, le=20971520)

    _audit_time = field_validator("audit_created_after")(timestamp)

    @field_validator("sources", "locations")
    @classmethod
    def names(cls, values):
        if any(not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value) for value in values):
            raise ValueError("INVALID_METADATA_OPTION")
        return list(dict.fromkeys(values))


class MetadataConnectionSpec(MetadataModel):
    schema_version: Literal[2] = 2
    name: str = Field(min_length=1, max_length=120)
    provider: Provider
    origin: str = Field(max_length=2048)
    edition: Literal["cloud", "self_managed", "data_center", "enterprise_cloud", "enterprise_server", "dedicated"] = "cloud"
    tenant: str = Field(default="", max_length=512)
    tenant_confirmed: bool = False
    scopes: list[MetadataScope] = Field(min_length=1, max_length=1000)
    capabilities: list[Capability] = Field(min_length=1, max_length=8)
    auth_type: Literal["bearer", "github_app"] = "bearer"
    secret_refs: dict[Literal["token", "username", "password", "app_id", "installation_id", "private_key", "client_id", "client_secret", "tenant_id", "bot_token", "app_token", "signing_secret", "admin_token", "audit_token", "refresh_token", "configuration_token"], str] = Field(default_factory=dict, max_length=16)
    principal_pin: str | None = Field(default=None, min_length=1, max_length=512)
    options: MetadataOptions = Field(default_factory=MetadataOptions)
    max_records: int = Field(default=50000, ge=1, le=250000)
    max_requests: int = Field(default=10000, ge=1, le=100000)
    max_pages: int = Field(default=10000, ge=1, le=100000)
    freshness_hours: int = Field(default=24, ge=1, le=168)
    schedule_minutes: int = Field(default=0, ge=0, le=10080)

    _origin = field_validator("origin")(canonical_origin)
    _labels = field_validator("name", "tenant")(metadata_text)

    @field_validator("principal_pin")
    @classmethod
    def principal(cls, value):
        return metadata_text(value) if value is not None else None

    @field_validator("secret_refs")
    @classmethod
    def references(cls, values):
        for ref in values.values():
            # Envelope syntax is a data contract. Do not import secret readers
            # (and their source registry) into this provider-independent model.
            if not isinstance(ref, str) or not 1 <= len(ref) <= (196608 if ref.startswith("sealed:v3:") else 32768):
                raise ValueError("INVALID_SECRET_REFERENCE")
            if ref.startswith("sealed:"):
                # v1 carries no key id; v2 names the key that sealed it.
                if not re.fullmatch(r"sealed:v1:[A-Za-z0-9_=-]{40,32758}"
                                    r"|sealed:v2:[0-9a-f]{16}:[A-Za-z0-9_=-]{40,32730}"
                                    r"|sealed:v3:[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+", ref):
                    raise ValueError("INVALID_SECRET_REFERENCE")
            elif ref.startswith("vault://"):
                path = ref[8:]
                if not path or not re.fullmatch(r"[A-Za-z0-9_./-]+", path) or any(p in (".", "..", "") for p in path.split("/")):
                    raise ValueError("INVALID_SECRET_REFERENCE")
            else:
                raise ValueError("SECRET_REFERENCE_REQUIRED")
        return values

    @model_validator(mode="after")
    def bounds(self):
        if not self.name.strip() or self.tenant_confirmed and not self.tenant:
            raise ValueError("NAME_OR_CONFIRMED_TENANT_REQUIRED")
        if len({(s.kind, s.id) for s in self.scopes}) != len(self.scopes) or len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("DUPLICATE_METADATA_SCOPE_OR_CAPABILITY")
        if "issuer_digest" in self.capabilities and (self.provider != "github" or "inventory" not in self.capabilities):
            raise ValueError("ISSUER_DIGEST_CAPABILITY_NOT_SUPPORTED")
        if self.options.include_provider_hashes and "issuer_digest" not in self.capabilities:
            raise ValueError("ISSUER_DIGEST_CAPABILITY_REQUIRED")
        if self.provider != "github" and (self.options.actions_run_days is not None
                                          or self.options.audit_scope != "both" or self.options.enterprise_only
                                          or not self.options.github_inventory
                                          or self.options.run_time_limit_minutes is not None):
            raise ValueError("GITHUB_OPTIONS_NOT_SUPPORTED")
        if self.options.include_audit_events and "audit" not in self.capabilities:
            raise ValueError("AUDIT_CAPABILITY_REQUIRED")
        return self


# Every node is named explicitly, including nested metadata. A container never
# grants permission to store arbitrary keys below it. Unknown source fields
# become MetadataOmission entries in the adapter instead of raw JSON blobs.
FACT_NAME_WORDS = """
id type kind entry length value values name display_name displayName label status state description username email
token_id credential_types user_id owner_id owner_status owner_profile_status issuer_id issuer_status issuer_profile_status
created_at_from_audit created_at updated_at expires_at last_used_at last_used_ips active revoked expired can_access_project
resource_type resource_id agent_id service_account_id access_level granular scopes granular_scopes observed_scopes
first_seen_at last_seen_at metadata_selection_policy metadata_merge_policy query_status unqueried_scopes
audit_event_id event_id action actor_id actor_name event_types target_type target_id inventory_match_status
inventory_match_reason candidate_inventory_ids source_id excluded_metadata_fields excluded_credential_fields
owner creator actor issuer profile granular_scope permission permissions metadata summary observations identity_scope
audit interpretation context spec handler endpoint params source_ids request_url excluded_credentials excluded_metadata
matching_events matching_creation_events event_refs candidate_inventory_id names_at_event candidate_ids author_id
author_name author_class details custom_message author_email ip_address user_agent entity_type entity_id reason
received retained filtered_out pages_completed records_seen completed_at config_hash collection_contract_version
started_at provider_retention_assumed requested_start effective_start lookback_days
creation_evidence evaluation_scope token_created_at_known token_created_at_status token_created_at
token_creation_time_covered oldest_window_searched newest_window_searched stop_reason stop_reasons
scope_coverage completed_ranges planned_ranges incomplete_windows start end
createdAt expiresAt lastActiveAt systemAccountId resource orgId keyType user createdBy serviceAccount clientId clientName
updatedAt clientRevokerId clientRevocationTime disabled tokenEndpointAuthMethod record_contract principal_kind
parent_states conflict_fields warnings atlassianId account_id account products lastAccess expiry disabledStatus
validServiceAccountIds invalidServiceAccountIds credentialsCount total fields derived source query coverage_basis
accepted_records invalid_records duplicate_observations observed_at provider_generated_at
added_on approved audience author avatar branch_match_kind branch_type clone comment commits committer cordoned
created_by created_on current date default_merge_strategy downloads expires_on fingerprint fork_policy forking_mode
forks full_name full_slug groups has_issues has_publicly_visible_repos has_wiki hash hooks hostname href html
is_personal is_privacy_enforced is_private key_id key_type labels language last_used links mainbranch markup
md5_fingerprint members merge_strategies message next oauth_client owners page pagelen parent parent_fingerprint
parents participants participated_on pattern pipelines_source_branches previous project projects public_key pullrequests
repositories repository role scm self sha256_fingerprint size slug snippets subkeys target token_endpoint updated_on
users uuid version watchers workspace jwks_uri authorization_endpoint scopes_supported response_types_supported
subject_types_supported id_token_signing_alg_values_supported claims_supported keys kty kid use alg n e x y crv x5c
x5t x5t#S256 apiToken.read profile.read profile.write lifecycle.enable lifecycle.disable lifecycle.delete
key restrictions api_targets browser_key_restrictions server_key_restrictions android_key_restrictions ios_key_restrictions
service methods allowed_referrers allowed_ips allowed_bundle_ids allowed_applications sha1_fingerprint package_name
project_id project_number location secret_id version_id service_account_email key_algorithm key_origin key_type
valid_after_time valid_before_time disabled_reason deleted rotation_period next_rotation_time labels tags enabled
created updated not_before expires managed content_type recoverable_days recovery_level uri key_ops vault_uri
installation_id app_id app_slug organization enterprise login repository_id repository_name repository_selection
single_file_name single_file_paths permissions_result permission_name actor_type event_type action_type visibility
token_type expires_in issued_at last_accessed_at authorized_user authorized_user_id creator_id scopes_requested
allow repository_ids integration_id audit_category audit_action client_id team_id enterprise_id bot_id is_bot
channel_id channel_name configuration_revision schema_version report_type collection_mode requested_account_ids
window_start window_end source_status source_reasons http_status reason_code retry_at contract_version code_commit
code_digest secret_version payload_crc32c resource_name secret_name annotations count result code identity subject
origin origin_id identities extern_uid saml_provider_id
target_kind relationship confidence match_basis observation_time effective_at state_basis missing_fields invalid_fields
sources source_name method path digest algorithm material_kind key_id scheme generated_at normalization_version
inventory_id identity instance namespace native_id family families first_seen last_seen first_seen_at_this_run
last_seen_at_this_run observation next_url cursor pages error at task_id stage code_location diagnostics
graphql_errors query_definition line column typeName fieldName metadata_policy canAccessProject expiresAt
lastUsed createdByUser webUrl
scope query_scope event_details_file evidence profile_status with_shared include_subgroups per_page pagination
order_by sort created_after created_before code_provenance execution_history created_by_user_id full_path parent_id
path_with_namespace web_url access group_id
operation mode stage attempt page_number row_index container_name completed data items field_types coverage run_status
requests received_records saved_records last_http_status page_count record_quality assessed_records identified_records
unique_identities duplicate_records unidentified_records identity_not_configured_records redactions secret_fields_omitted
sensitive_values_omitted truncated_nodes normalized_utc expired_at_observation provider environment queried_org_id
connection_profile finished_at inventory_complete requested_sources limits max_pages max_records max_requests max_seconds
timeout retries max_retry_wait max_targets max_targets_per_kind page_size pageSize org_api_tokens_page_size target_discovery
service_account_ids user_ids oauth_client_ids invalid_identifiers targets targets_omitted_by_limit key_details_omitted_by_limit
runner_details_omitted_by_limit count_ids_exceeding_contract_limit not_requested_no_observed_targets not_requested_by_configuration
not_requested_operations not_requested_by_mode public_listing_contract_unverified count_comparisons listing count_operation
listed_unique_ids reported_count equal_at_observation proves_completeness identity_link_candidates provider_id kinds basis
comparison_scope requested_account_count
counts unambiguous_credentials conflicted_identities identities warning_counts
appType userStatus allowed access_tokens container serviceAccountId namespaces issuer_name audit_event_counts
event_name target_details locations consecutive_429 retry_after_seconds
feature replacement collection_scope collector_version access_billable account_status account_type apiToken.delete
characteristics createdById department email.set extended_profile job_title last_active lifecycle.enablement locale
meta nickname not_mentionable picture prev product_access url zoneinfo
uid deleted_at destroyed_at lifecycle_state value_read_status error_code error_counts
objects_seen pages_read accounts_checked accounts_seen locations_seen locations_checked
keys_checked series_seen points_seen selection api_states relation evidence_source evidence_id
evidence_class coverage_path log_name insert_id method_name request_count caller_identity
policy_resource condition_present effective_access
inherited_policies deny_policies principal_access_boundaries membership_resolution condition_evaluation
@timestamp _document_id access_granted_at access_tokens_url actor_ip actor_is_agent actor_is_bot
actor_location added_by age_days allowed_actions application application_client_id application_id
application_name application_type archived authorization_count authorization_id organization_id
authorization_state authorized_credential_expires_at authorized_credential_id
authorized_credential_note authorized_credential_title authorized_organizations avatar_url
business business_id can_approve_pull_request_reviews checks conclusion credential_accessed_at
credential_authorized_at credential_id credential_instance_count credential_state credential_type
default_branch default_workflow_permissions effective_access_state enterprise_authorized event
events exempt_administrators expiry_status expiry_unknown explanation has_multiple_single_files
head_branch head_repository head_sha html_url installation integration item_type jobs
key_metadata_error managed_oauth_access_id managed_oauth_scopes managed_token_id
managed_token_scopes never_expires new_state next_expires_at node_id oauth_application
oauth_application_id oauth_credential_type old_access old_permissions old_scopes
old_token_expiration operation_type org org_id owner_type past_expiration_policy
past_expiration_policy_basis policy previous_state private programmatic_access_type
public_key_last_used public_repo pushed_at read_only repo repo_id repositories_url request_id
requested_repositories require_approval_for_fork_pr_workflows run run_attempt run_id run_number
run_started_at run_workflows_from_fork_pull_requests runner_group_id runner_group_name runner_id
runner_name send_secrets_and_variables send_write_tokens_to_workflows sha_pinning_required
site_admin source_endpoint source_scope state_reason suspended_at suspended_by title
token_expiration token_expired token_expires_at token_last_eight token_last_used_at token_name
token_scopes triggering_actor user_programmatic_access_id user_programmatic_access_name
user_programmatic_access_request_id verified workflow_id workflow_name workflow_runs
revoked_at revoked_by client workspaces is_enterprise_managed idp_issuer last_active_at
environment_scope variable_type protected masked hidden variable_raw usage_type can_push is_admin
developer_type is_internal approved_at approved_by last_change last_change_at
"""
FACT_NAMES = frozenset(FACT_NAME_WORDS.split())
_FORBIDDEN_FACTS = {"secret", "secret_key", "secret_access_key", "access_token", "refresh_token", "session_token", "client_secret", "private_key", "authorization", "raw", "raw_content", "raw_secret", "password"}
FactScalar = StrictStr | StrictInt | StrictFloat | StrictBool


class MetadataFact(MetadataModel):
    name: str = Field(min_length=1, max_length=512)
    state: Literal["PRESENT", "NULL", "MISSING", "INVALID"] = "PRESENT"
    value: FactScalar | list[FactScalar] | None = None
    container: Literal["object", "array"] | None = None
    children: list[MetadataFact] = Field(default_factory=list, max_length=512)
    reason: Code | None = None

    @field_validator("name")
    @classmethod
    def field_name(cls, value):
        # Optional JSON pointer retains an adapter's exact field path, but every
        # nonnumeric path segment is still checked against the approved names.
        parts = value.strip("/").split("/")
        if any((part not in FACT_NAMES and not part.isdecimal()) or part.lower() in _FORBIDDEN_FACTS for part in parts):
            raise ValueError("UNAPPROVED_METADATA_FIELD")
        return value

    @model_validator(mode="after")
    def shape(self):
        if self.state != "PRESENT" and (self.value is not None or self.children or self.container is not None):
            raise ValueError("ABSENT_OR_INVALID_FACT_HAS_VALUE")
        if self.value is not None and self.children:
            raise ValueError("FACT_SCALAR_AND_CHILDREN")
        if self.container is not None and self.value is not None:
            raise ValueError("FACT_CONTAINER_AND_VALUE")
        if self.container != "array" and len({c.name for c in self.children}) != len(self.children):
            raise ValueError("DUPLICATE_METADATA_FIELD")
        if self.state == "INVALID" and self.reason is None:
            raise ValueError("INVALID_FACT_REASON_REQUIRED")
        values = self.value if isinstance(self.value, list) else [self.value]
        if len(values) > 1000:
            raise ValueError("FACT_VALUE_LIMIT")
        for value in values:
            if isinstance(value, str):
                public_block = (self.name.strip("/").split("/")[-1] in ("public_key", "key", "entry")
                                and value.startswith(("-----BEGIN PUBLIC KEY-----", "-----BEGIN PGP PUBLIC KEY BLOCK-----")))
                if public_block:
                    if len(value) > 65536 or _SECRET.search(value) or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
                        raise ValueError("UNSAFE_PUBLIC_KEY_METADATA")
                else:
                    metadata_text(value)
                if value.lstrip().startswith(("{", "[")):
                    try:
                        decoded = json.loads(value)
                    except (ValueError, RecursionError):
                        decoded = None
                    if isinstance(decoded, (dict, list)):
                        raise ValueError("SERIALIZED_PAYLOAD_NOT_ALLOWED")
            if isinstance(value, float) and not (-1e100 < value < 1e100):
                raise ValueError("INVALID_FACT_NUMBER")
        return self


class MetadataOmission(MetadataModel):
    path: str = Field(min_length=1, max_length=512)
    reason: Code

    _path = field_validator("path")(metadata_text)


class MetadataPermission(MetadataModel):
    kind: Literal["scope", "permission", "role", "repository_grant", "restriction"] = "permission"
    name: str = Field(min_length=1, max_length=256)
    resource_kind: str = Field(default="", max_length=64)
    resource_id: str = Field(default="", max_length=512)
    effect: Literal["ALLOW", "DENY", "UNKNOWN"] = "UNKNOWN"
    actions: list[str] = Field(default_factory=list, max_length=250)
    conditions: list[MetadataFact] = Field(default_factory=list, max_length=100)

    _labels = field_validator("name", "resource_kind", "resource_id")(metadata_text)

    @field_validator("actions")
    @classmethod
    def safe_actions(cls, values):
        return [metadata_text(value) for value in values]


class EntityIdentity(MetadataModel):
    provider: Provider
    origin: str
    tenant: str = Field(default="", max_length=512)
    tenant_confirmed: bool = False
    kind: ObjectKind
    object_id: str = Field(min_length=1, max_length=2048)

    _origin = field_validator("origin")(canonical_origin)
    _labels = field_validator("tenant", "object_id")(metadata_text)

    def key(self, connection_id) -> str:
        tenancy = self.tenant if self.tenant_confirmed else "connection:" + str(connection_id)
        return digest([2, self.provider, self.origin, tenancy, self.kind, self.object_id])


class MetadataProvenance(MetadataModel):
    operation: str = Field(min_length=1, max_length=128)
    observed_at: str = Field(max_length=40)
    resource_id: str = Field(default="", max_length=2048)
    provider_generated_at: str | None = Field(default=None, max_length=40)
    source_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    contract_version: str = Field(default="1", max_length=64)

    _labels = field_validator("operation", "resource_id", "contract_version")(metadata_text)
    _times = field_validator("observed_at", "provider_generated_at")(timestamp)


class MetadataValueMatch(MetadataModel):
    evidence: Literal["VALUE", "PROVIDER_DIGEST", "IDENTIFIER", "UNRESOLVED"]
    reference: str = Field(min_length=1, max_length=2048)
    version: str = Field(default="", max_length=256)
    version_state: Literal["CURRENT", "PREVIOUS", "DELETED", "DESTROYED", "UNKNOWN"] = "UNKNOWN"
    credential_type: Code = "UNKNOWN"
    fingerprint: Digest | None = None
    provider_digest: Digest | None = None
    session_fingerprint: Digest | None = None
    identifier: str = Field(default="", max_length=512)
    scheme: FingerprintScheme = SCHEME
    key_id: Digest
    material_kind: Literal["credential", "component"] = "credential"
    engine_digest: Digest
    policy_digest: Digest
    read_at: str = Field(max_length=40)
    reason: Code | None = None

    _labels = field_validator("reference", "version", "identifier")(metadata_text)
    _time = field_validator("read_at")(timestamp)

    @model_validator(mode="after")
    def evidence_fields(self):
        if self.session_fingerprint is not None and (self.evidence != "VALUE" or self.credential_type != "AWS_ACCESS_KEY"
                                                    or not re.fullmatch(r"ASIA[A-Z0-9]{16}", self.identifier)):
            raise ValueError("SESSION_VALUE_EVIDENCE_REQUIRED")
        if self.provider_digest is not None and (self.evidence != "VALUE" or self.credential_type != "GITHUB_TOKEN"):
            raise ValueError("GITHUB_VALUE_DIGEST_REQUIRED")
        if (self.evidence in {"VALUE", "PROVIDER_DIGEST"}) != (self.fingerprint is not None):
            raise ValueError("VALUE_FINGERPRINT_REQUIRED")
        if (self.evidence == "PROVIDER_DIGEST") != (self.scheme == "github-token-sha256/hmac-sha256-v1"):
            raise ValueError("PROVIDER_DIGEST_SCHEME_REQUIRED")
        if self.evidence == "IDENTIFIER" and not self.identifier:
            raise ValueError("IDENTIFIER_REQUIRED")
        if self.evidence == "UNRESOLVED" and self.reason is None:
            raise ValueError("VALUE_FAILURE_REASON_REQUIRED")
        return self


class MetadataValueContract(MetadataModel):
    scheme: FingerprintScheme = SCHEME
    key_id: Digest
    material_kind: Literal["credential", "component"] = "credential"
    engine_digest: Digest
    policy_digest: Digest


class MetadataRecordBase(MetadataModel):
    scope: MetadataScope
    purpose: Purpose = "issuer_inventory"
    provenance: MetadataProvenance
    facts: list[MetadataFact] = Field(default_factory=list, max_length=512)
    omissions: list[MetadataOmission] = Field(default_factory=list, max_length=512)

    @model_validator(mode="after")
    def bounded_facts(self):
        if len({f.name for f in self.facts}) != len(self.facts):
            raise ValueError("DUPLICATE_METADATA_FIELD")
        pending = [(f, 1) for f in self.facts]
        if hasattr(self, "permissions"):
            pending.extend((f, 1) for p in self.permissions for f in p.conditions)
        count = 0
        while pending:
            fact, depth = pending.pop()
            count += 1
            if depth > 6 or count > 2048:
                raise ValueError("METADATA_FACT_LIMIT")
            pending.extend((child, depth + 1) for child in fact.children)
        return self


class IdentityKey(MetadataModel):
    """One keyed digest of an identity value and what it is; private, never exported."""
    kind: IdentityKeyKind
    digest: Digest


class EntityObservation(MetadataRecordBase):
    record_type: Literal["entity_observation"] = "entity_observation"
    identity: EntityIdentity
    permissions: list[MetadataPermission] = Field(default_factory=list, max_length=250)
    provider_state: str = Field(default="UNKNOWN", max_length=64)
    normalized_state: Literal["ACTIVE", "INACTIVE", "EXPIRED", "REVOKED", "DELETED", "DISABLED", "PENDING", "UNKNOWN"] = "UNKNOWN"
    state_basis: Literal["PROVIDER_REPORTED", "OBSERVED", "UNKNOWN"] = "UNKNOWN"
    effective_at: str | None = Field(default=None, max_length=40)
    value_match: MetadataValueMatch | None = None
    # Private: keyed digests that link a person or account (cremore.identity.keys).
    identity_keys: list[IdentityKey] = Field(default_factory=list, max_length=16)
    identity_key_id: Digest | None = None

    _state = field_validator("provider_state")(metadata_text)
    _effective = field_validator("effective_at")(timestamp)

    @model_validator(mode="after")
    def identity_digests(self):
        if (self.identity_keys or self.identity_key_id) and (
                self.purpose != "identity_status" or self.identity.kind != "principal"
                or not self.identity_keys or self.identity_key_id is None):
            raise ValueError("IDENTITY_KEYS_REQUIRE_AN_IDENTITY_PRINCIPAL")
        if len({(k.kind, k.digest) for k in self.identity_keys}) != len(self.identity_keys):
            raise ValueError("DUPLICATE_IDENTITY_KEY")
        return self


class MetadataRelation(MetadataRecordBase):
    record_type: Literal["relation"] = "relation"
    subject: EntityIdentity
    target: EntityIdentity
    relation: Literal["owns", "created_by", "used", "can_access", "grants", "member_of", "contains", "installed_on", "authorized_by", "provider_reference", "candidate_match", "stored_in", "revoked_by"]
    match_basis: Literal["PROVIDER_ID", "PROVIDER_EXPLICIT", "AUDIT_REFERENCE", "IDENTIFIER", "CANDIDATE", "POLICY"]
    confidence: Literal["EXACT", "IDENTIFIER", "CANDIDATE", "UNKNOWN"] = "UNKNOWN"
    window_start: str | None = None
    window_end: str | None = None

    _times = field_validator("window_start", "window_end")(timestamp)

    @model_validator(mode="after")
    def evidence_confidence(self):
        if self.confidence == "EXACT" and self.match_basis in ("CANDIDATE", "IDENTIFIER", "POLICY"):
            raise ValueError("RELATION_CONFIDENCE_CONFLICT")
        return self


class ProviderEvent(MetadataRecordBase):
    record_type: Literal["provider_event"] = "provider_event"
    event_id: str = Field(min_length=1, max_length=512)
    event_type: str = Field(min_length=1, max_length=128)
    occurred_at: str = Field(max_length=40)
    subject: EntityIdentity | None = None
    target: EntityIdentity | None = None
    match_basis: Literal["PROVIDER_ID", "PROVIDER_EXPLICIT", "AUDIT_REFERENCE", "IDENTIFIER", "CANDIDATE", "UNKNOWN"] = "UNKNOWN"
    confidence: Literal["EXACT", "IDENTIFIER", "CANDIDATE", "UNKNOWN"] = "UNKNOWN"
    value_match: MetadataValueMatch | None = None

    _labels = field_validator("event_id", "event_type")(metadata_text)
    _time = field_validator("occurred_at")(timestamp)

    @model_validator(mode="after")
    def evidence_confidence(self):
        if self.confidence == "EXACT" and self.match_basis in ("CANDIDATE", "IDENTIFIER", "UNKNOWN"):
            raise ValueError("EVENT_CONFIDENCE_CONFLICT")
        return self


class RecordQuality(MetadataModel):
    records: int = Field(default=0, ge=0)
    identified: int = Field(default=0, ge=0)
    missing_id: int = Field(default=0, ge=0)
    invalid_id: int = Field(default=0, ge=0)
    duplicates: int = Field(default=0, ge=0)
    conflicting: int = Field(default=0, ge=0)
    invalid_records: int = Field(default=0, ge=0)
    assessed_records: int = Field(default=0, ge=0)
    identified_records: int = Field(default=0, ge=0)
    unique_identities: int = Field(default=0, ge=0)
    duplicate_records: int = Field(default=0, ge=0)
    unidentified_records: int = Field(default=0, ge=0)
    identity_not_configured_records: int = Field(default=0, ge=0)


class FieldCatalogEntry(MetadataModel):
    path: str = Field(min_length=1, max_length=512)
    types: list[Literal["null", "string", "number", "boolean", "object", "array", "integer", "missing", "invalid"]] = Field(min_length=1, max_length=9)

    _path = field_validator("path")(metadata_text)


class OperationReport(MetadataRecordBase):
    record_type: Literal["operation_report"] = "operation_report"
    status: Literal["COMPLETE", "PARTIAL", "FAILED", "UNSUPPORTED", "UNKNOWN", "NOT_REQUESTED"]
    reasons: list[Code] = Field(default_factory=list, max_length=100)
    pages: int = Field(default=0, ge=0, le=100000)
    received_records: int = Field(default=0, ge=0, le=10000000)
    saved_records: int = Field(default=0, ge=0, le=10000000)
    expected_records: int | None = Field(default=None, ge=0, le=10000000)
    proves_completeness: bool = False
    record_quality: RecordQuality = Field(default_factory=RecordQuality)
    field_catalog: list[FieldCatalogEntry] = Field(default_factory=list, max_length=512)
    shape: Literal["object", "array", "scalar", "empty", "unknown"] = "unknown"
    native_schema_version: str = Field(default="", max_length=64)
    report_type: str = Field(default="", max_length=128)
    collection_mode: str = Field(default="", max_length=64)
    window_start: str | None = None
    window_end: str | None = None
    value_access: Literal["NOT_REQUESTED", "COMPLETE", "PARTIAL", "FAILED"] = "NOT_REQUESTED"
    value_contract: MetadataValueContract | None = None

    _labels = field_validator("native_schema_version", "report_type", "collection_mode")(metadata_text)
    _times = field_validator("window_start", "window_end")(timestamp)


MetadataRecord = Annotated[EntityObservation | MetadataRelation | ProviderEvent | OperationReport, Field(discriminator="record_type")]
RECORD_ADAPTER = TypeAdapter(MetadataRecord)


class MetadataContract(MetadataModel):
    schema_version: Literal[2] = 2
    tool_version: Literal["0.1.0"] = "0.1.0"
    normalization_version: Literal["cremore-provider-metadata-v1"] = "cremore-provider-metadata-v1"
    scope_digest: Digest
    principal_id: str | None = Field(default=None, max_length=512)
    principal_verified: bool = False
    spec_snapshot: MetadataConnectionSpec | None = None

    @field_validator("principal_id")
    @classmethod
    def principal(cls, value):
        return metadata_text(value) if value is not None else None

    @model_validator(mode="after")
    def identity_proof(self):
        if self.principal_verified and not self.principal_id:
            raise ValueError("VERIFIED_PRINCIPAL_REQUIRED")
        if self.spec_snapshot is not None and self.spec_snapshot.secret_refs:
            raise ValueError("CONTRACT_SECRET_REFERENCES_FORBIDDEN")
        return self


def metadata_contract(spec, *, principal_id=None, principal_verified=False):
    return MetadataContract(scope_digest=digest(spec.model_dump()), principal_id=principal_id,
                            principal_verified=principal_verified,
                            spec_snapshot=MetadataConnectionSpec.model_validate({**spec.model_dump(), "secret_refs": {}}))


# A scope digest covers every option of the model, defaults included, so a release
# that only adds an option moves the digest of every stored connection and run.
# Callers of these two also require the same revision, within which the stored spec
# cannot change: only code can make the digests differ, and that is all they forgive.
def same_contract(a, b):
    """Two stored run contracts bind the same scope and principal, read through today's model."""
    left, right = MetadataContract.model_validate(a), MetadataContract.model_validate(b)
    if left.spec_snapshot is None or right.spec_snapshot is None:
        return left == right
    return left.model_dump(exclude={"scope_digest"}) == right.model_dump(exclude={"scope_digest"})


def scope_matches(contract, spec):
    """A stored run contract binds this connection spec (a stored dict or a model)."""
    current = spec if isinstance(spec, MetadataConnectionSpec) else MetadataConnectionSpec.model_validate(spec)
    stored = MetadataContract.model_validate(contract)
    if stored.spec_snapshot is None:
        return stored.scope_digest in {digest(current.model_dump()), digest(spec) if isinstance(spec, dict) else ""}
    return stored.spec_snapshot == metadata_contract(current).spec_snapshot


class MetadataStart(MetadataModel):
    revision: int = Field(ge=1)
    request_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    contract: MetadataContract


class MetadataBatch(MetadataModel):
    schema_version: Literal[2] = 2
    index: int = Field(ge=0, le=100000)
    items: list[MetadataRecord] = Field(min_length=1, max_length=MAX_BATCH)

    @model_validator(mode="after")
    def byte_limit(self):
        if len(self.model_dump_json().encode()) > 2000000:
            raise ValueError("METADATA_BATCH_LIMIT")
        return self


class MetadataFinish(MetadataModel):
    schema_version: Literal[2] = 2
    batch_count: int = Field(ge=0, le=100000)
    item_count: int = Field(ge=0, le=250000)
    status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    reasons: list[Code] = Field(default_factory=list, max_length=100)


class MetadataPage(MetadataModel):
    records: list[MetadataRecord] = Field(default_factory=list, max_length=5000)
    checkpoint: dict = Field(default_factory=dict)
    principal_id: str | None = Field(default=None, max_length=512)
    principal_verified: bool = False
    status: Literal["COMPLETE", "PARTIAL", "FAILED", "WAITING"] | None = None
    reasons: list[Code] = Field(default_factory=list, max_length=100)
    retry_after_seconds: int = Field(default=60, ge=1, le=3600)

    @field_validator("checkpoint")
    @classmethod
    def safe_checkpoint(cls, value):
        return checkpoint_json(value)


def checkpoint_json(value):
    value = safe_task_state(value)
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 24 or count > 100000:
            raise ValueError("METADATA_CHECKPOINT_LIMIT")
        if isinstance(node, dict):
            pending.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            pending.extend((v, depth + 1) for v in node)
        elif isinstance(node, str) and (_SECRET.search(node) or _CONTROL.search(node)):
            raise ValueError("UNSAFE_METADATA_CHECKPOINT")
    return value


def entity_id(identity: EntityIdentity, connection_id) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, "cremore:coverage-entity:" + identity.key(connection_id))


def in_metadata_scope(spec: MetadataConnectionSpec, item: MetadataRecord) -> bool:
    if item.scope not in spec.scopes:
        return False
    identities = ([item.identity] if isinstance(item, EntityObservation) else
                  [i for i in (getattr(item, "subject", None), getattr(item, "target", None)) if i])
    if any((i.provider, i.origin, i.tenant, i.tenant_confirmed) !=
           (spec.provider, spec.origin, spec.tenant, spec.tenant_confirmed) for i in identities):
        return False
    capability = ("relations" if isinstance(item, MetadataRelation) else "audit" if isinstance(item, ProviderEvent)
                  else "vault_metadata" if item.purpose == "vault_metadata"
                  else "identity_status" if item.purpose == "identity_status" else "inventory")
    if capability not in spec.capabilities:
        return False
    if isinstance(item, ProviderEvent) and item.value_match is not None:
        # GitHub's audit hash of the token behind an activity summary, or of the
        # managed token an SSO authorization entry names, keyed for the
        # installation; it names that one event and nothing else.
        match = item.value_match
        return (spec.provider == "github" and item.purpose == "usage"
                and (item.event_type == "token_activity" or item.event_type.startswith("org_credential_authorization."))
                and item.scope.kind == "enterprise" and spec.options.include_provider_hashes
                and "issuer_digest" in spec.capabilities and match.evidence == "PROVIDER_DIGEST"
                and match.credential_type == "GITHUB_TOKEN" and match.material_kind == "credential"
                and match.reference == item.event_id and not match.version and match.version_state == "UNKNOWN")
    if isinstance(item, EntityObservation) and item.value_match is not None:
        match = item.value_match
        if match.evidence == "PROVIDER_DIGEST":
            return (spec.provider == "github" and item.purpose == "issuer_inventory"
                    and item.identity.kind == "credential" and item.scope.kind == "enterprise"
                    and spec.options.include_provider_hashes and "issuer_digest" in spec.capabilities
                    and match.material_kind == "credential" and match.reference == item.identity.object_id
                    and not match.version and match.version_state == "UNKNOWN")
        return False
    if isinstance(item, OperationReport) and (item.value_access != "NOT_REQUESTED" or item.value_contract is not None):
        if item.value_contract is not None and item.value_contract.scheme == "github-token-sha256/hmac-sha256-v1":
            return (spec.provider == "github" and item.purpose == "issuer_inventory"
                    and item.scope.kind == "enterprise" and spec.options.include_provider_hashes
                    and "issuer_digest" in spec.capabilities and item.value_contract.material_kind == "credential")
        return False
    return True
