"""SQLAlchemy Core table definitions — the platform's schema of record.

Types are the SQLAlchemy generic forms (Uuid, JSON, DateTime) so the same
schema materialises on PostgreSQL in production and on SQLite in tests via
``metadata.create_all``. ``cremore.db.sql.create_all`` creates missing tables and
adds missing (nullable) columns, so an upgrade needs no separate migration
step for additive changes.
"""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    and_,
    cast,
    func,
)

from cremore.domain.models import CONTENT_SCAN_KINDS

metadata = MetaData()


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


schema_migrations = Table(
    "schema_migrations", metadata,
    Column("version", Integer, primary_key=True),
    Column("name", Text, nullable=False),
    Column("applied_at", DateTime(timezone=True), nullable=False, default=_now),
)

trigger_receipts = Table(
    "scan_trigger_receipts", metadata,
    Column("receipt_key", Text, primary_key=True),
    Column("job_id", Uuid, nullable=False),
    Column("plan_id", Uuid, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now, index=True),
)

# Original records remain recoverable after offline identity consolidation.
migration_archive = Table(
    "migration_archive", metadata,
    Column("id", Uuid, primary_key=True),
    Column("migration_version", Integer, nullable=False),
    Column("table_name", Text, nullable=False),
    Column("original_id", Uuid, nullable=False),
    Column("canonical_id", Uuid, nullable=False),
    Column("record", JSON, nullable=False),
    Column("archived_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("migration_version", "table_name", "original_id", name="migration_archive_record_key"),
)


credentials = Table(
    "credentials",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("fingerprint", Text, nullable=False),
    Column("credential_type", Text, nullable=False),
    Column("identifier", Text),
    Column("identifier_hint", Text),
    Column("provider", Text),
    Column("aws_account_id", Uuid),
    Column("principal_name", Text),
    Column("principal_arn", Text),
    Column("principal_arn_source", Text),  # additive: ACTIVE_VERIFICATION | IAM_OWNER_LOOKUP | IAM_INVENTORY
    Column("business_owner", Text),
    Column("team", Text),
    Column("service_name", Text),
    Column("credential_status", Text, nullable=False, default="UNKNOWN"),
    Column("owner_status", Text, nullable=False, default="UNKNOWN"),
    Column("last_used_at", DateTime(timezone=True)),
    Column("last_used_service", Text),
    Column("last_used_region", Text),
    Column("credential_created_at", DateTime(timezone=True)),
    Column("usage_snapshot", JSON),  # additive: last observed-use lookup
    Column("management_reference", Text),  # additive: declared secret-manager ARN
    Column("management_revision", Integer),
    Column("management_updated_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("fingerprint", "credential_type", name="credentials_fingerprint_credential_type_key"),
)

exposures = Table(
    "exposures",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("identity_key", Text, nullable=True),
    Column("resource_key", Text, nullable=True),
    Column("container_key", Text, nullable=True),
    Column("credential_id", Uuid, ForeignKey("credentials.id", ondelete="CASCADE"), nullable=False),
    Column("source_type", Text, nullable=False),
    Column("resource_arn", Text),
    Column("resource_name", Text, nullable=False),
    Column("location", Text, nullable=False),
    Column("object_version", Text, nullable=False, default=""),
    Column("line_number", Integer),
    Column("severity", Text, nullable=False),
    Column("status", Text, nullable=False, default="OPEN"),
    Column("redacted_line", Text),
    Column("redaction_version", Integer),
    Column("aws_account_id", Uuid),
    Column("first_scan_id", Uuid),
    Column("last_scan_id", Uuid),
    Column("source_connection_id", Uuid),
    Column("first_source_scan_id", Uuid),
    Column("last_source_scan_id", Uuid),
    Column("first_seen_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("last_seen_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("removed_at", DateTime(timezone=True)),
    Column("metadata", JSON, nullable=False, default=dict),
)

scan_jobs = Table(
    "scan_jobs",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("kind", Text, nullable=False),  # inline | s3 | github | notion
    Column("status", Text, nullable=False, default="QUEUED"),  # QUEUED|RUNNING|SUCCEEDED|FAILED|CANCELLED
    Column("payload", JSON, nullable=False, default=dict),
    Column("connection_id", Uuid),
    Column("objects", Integer, nullable=False, default=0),
    Column("findings", Integer, nullable=False, default=0),
    Column("objects_failed", Integer),  # additive, nullable: listed but unreadable
    Column("coverage", JSON),  # additive, nullable: scoped-run coverage counters
    Column("error", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("started_at", DateTime(timezone=True)),
    Column("finished_at", DateTime(timezone=True)),
    # additive, nullable: "event" or "sweep" (cremore.db.repository.job_lane), set at every insert; NULL rows
    # from before the column count as sweeps.
    Column("lane", Text),
)
# One executing content run per connection and lane, so a change event's run
# need not wait out a long sweep of the same connection. Admission remains
# durable while busy. Repository claims also serialize unscoped legacy runs
# against all scoped runs; this unique index is the same-slot backstop.
_active_content_scan = and_(scan_jobs.c.status.in_(("RUNNING", "CANCELLING")), scan_jobs.c.kind.in_(CONTENT_SCAN_KINDS))
ONE_ACTIVE_CONTENT_SCAN = Index("scan_jobs_one_running_connection", func.coalesce(cast(scan_jobs.c.connection_id, String), "unscoped"),
                                func.coalesce(scan_jobs.c.lane, "sweep"), unique=True,
                                postgresql_where=_active_content_scan, sqlite_where=_active_content_scan)

connections = Table(
    "connections",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("provider", Text, nullable=False),  # aws | github | notion
    Column("name", Text, nullable=False),
    Column("status", Text, nullable=False, default="PENDING"),  # PENDING|ACTIVE|DISABLED|ERROR
    Column("config", JSON, nullable=False, default=dict),  # non-secret scope only
    Column("secret_ref", Text),  # pointer into the secret store, never the secret
    Column("last_error", Text),
    Column("last_verified_at", DateTime(timezone=True)),
    Column("credential_evidence", JSON),  # additive: last credential-check outcome
    # additive: last read of GitHub's own secret-scanning alerts. Alert metadata
    # only; the API returns the raw secret and this never carries it.
    Column("secret_scanning", JSON),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("provider", "name", name="connections_provider_name_key"),
)

findings = Table(
    "findings",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("credential_id", Uuid, ForeignKey("credentials.id", ondelete="CASCADE"), nullable=False, unique=True),
    Column("primary_exposure_id", Uuid, nullable=False),
    Column("severity", Text, nullable=False),
    Column("all_locations_removed", Boolean),
    Column("workflow_status", Text, nullable=False, default="OPEN"),
    Column("assigned_to", Text),
    Column("acknowledged_at", DateTime(timezone=True)),
    Column("resolved_at", DateTime(timezone=True)),
    Column("resolution", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

# Immutable observations survive later finding deletion and destination changes.
# finding_id is set for finding.created only; operational events carry none.
siem_events = Table(
    "siem_events", metadata,
    Column("event_id", Uuid, primary_key=True),
    Column("finding_id", Uuid, nullable=True, unique=True),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("payload", JSON, nullable=False),
)
Index("siem_events_order", siem_events.c.occurred_at, siem_events.c.event_id)

siem_deliveries = Table(
    "siem_deliveries", metadata,
    Column("destination", String(128), primary_key=True),
    Column("event_id", Uuid, ForeignKey("siem_events.event_id"), primary_key=True),
    Column("attempts", Integer, nullable=False, default=0),
    Column("token", Uuid),
    Column("lease_until", DateTime(timezone=True)),
    Column("available_at", DateTime(timezone=True), nullable=False),
    Column("delivered_at", DateTime(timezone=True)),
    Column("error_code", String(64)),
    # additive: set when the exporter stopped retrying (max_attempts); an Admin releases it.
    Column("held_at", DateTime(timezone=True)),
)
# What SiemOutbox.claim_owed reads each alert pass: a destination's rows not received yet, the earliest due first.
SIEM_OWED_INDEX = Index("siem_deliveries_owed", siem_deliveries.c.destination, siem_deliveries.c.available_at,
                        postgresql_where=siem_deliveries.c.delivered_at.is_(None),
                        sqlite_where=siem_deliveries.c.delivered_at.is_(None))

# What the exporter last saw per destination. Codes and times only; never options or endpoints.
siem_destination_status = Table(
    "siem_destination_status", metadata,
    Column("destination", String(128), primary_key=True),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("last_success_at", DateTime(timezone=True)),
    Column("last_failure_at", DateTime(timezone=True)),
    Column("last_error_code", String(64)),
    Column("consecutive_failures", Integer, nullable=False, default=0),
)

aws_accounts = Table(
    "aws_accounts",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("account_id", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("environment", Text, nullable=False, default=""),
    Column("scanner_role_arn", Text),
    Column("remediation_role_arn", Text),
    Column("enabled", Integer, nullable=False, default=1),
    Column("validation_status", Text, nullable=False, default="PENDING"),
    # Additive, nullable columns (added in place by create_all on upgrade).
    Column("external_id", Text),  # STS ExternalId for the member role; not a secret
    Column("declaration", JSON),  # administrator declaration; never observed evidence
    Column("validation_detail", Text),  # safe reason code of the last worker-side check
    Column("validated_at", DateTime(timezone=True)),
    Column("access", Text),  # ROLE | RUNTIME_IDENTITY | SSO_PERMISSION_SET (NULL = ROLE)
    Column("sso_role_name", Text),  # SSO_PERMISSION_SET only: the assigned permission set name
    Column("access_revision", Integer),  # scanner purpose; NULL = 1
    Column("remediation_access_revision", Integer),  # NULL = 1
    Column("validation_key", Text),  # "<access_revision>:<approval_revision>" of the stored scanner result
    Column("remediation_validation_status", Text),
    Column("remediation_validation_detail", Text),
    Column("remediation_validated_at", DateTime(timezone=True)),
    Column("remediation_validation_key", Text),
    Column("source", Text),  # MANUAL | ORGANIZATION | SSO
    Column("org_state", Text),  # facts from the last complete organization sync
    Column("org_present", Boolean),
    Column("in_deployment_scope", Boolean),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("account_id", name="aws_accounts_account_id_key"),
)

governance_reviews = Table(
    "governance_reviews",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("finding_id", Uuid, nullable=False),
    Column("kind", Text, nullable=False, default="OWNERSHIP"),
    Column("status", Text, nullable=False, default="OPEN"),
    Column("assignee", Text),
    Column("question", Text, nullable=False, default=""),
    Column("response", Text),
    Column("created_by", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("resolved_at", DateTime(timezone=True)),
)

rotation_jobs = Table(
    "rotation_jobs",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("credential_id", Uuid, nullable=False),
    Column("status", Text, nullable=False, default="REQUESTED"),
    Column("phase", Text, nullable=False, default="PREPARE"),
    Column("requested_by", Text, nullable=False, default=""),
    Column("approved_by", Text),
    Column("error", Text),
    # bound plan: identifiers only, never key material
    Column("secret_arn", Text, nullable=False, default=""),
    Column("user_name", Text, nullable=False, default=""),
    Column("account_id", Text, nullable=False, default=""),
    Column("old_key_id", Text, nullable=False, default=""),
    Column("expected_current_version", Text, nullable=False, default=""),
    Column("new_key_id", Text),
    Column("pending_version", Text),
    Column("access_pin", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

management_actions = Table(
    "management_actions",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("finding_id", Uuid, nullable=False),
    Column("action_type", Text, nullable=False),
    Column("status", Text, nullable=False, default="PENDING"),
    Column("requested_by", Text, nullable=False, default=""),
    Column("confirmed_by", Text),
    Column("note", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

custom_rules = Table(
    "custom_rules",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("name", Text, nullable=False),
    Column("description", Text, nullable=False, default=""),
    Column("enabled", Integer, nullable=False, default=1),
    Column("rule_type", Text, nullable=False, default="regex"),
    Column("keywords", JSON, nullable=False, default=list),
    Column("pattern", Text, nullable=False),
    Column("severity", Text, nullable=False, default="HIGH"),
    Column("revision", Integer, nullable=False, default=1),
    Column("scope_sources", JSON, nullable=False, default=list),
    Column("include_globs", JSON, nullable=False, default=list),
    Column("exclude_globs", JSON, nullable=False, default=list),
    Column("exclude_words", JSON, nullable=False, default=list),
    Column("provider_candidates", JSON, nullable=False, default=list),
    Column("content_kinds", JSON, nullable=False, default=list),
    Column("category", Text),
    Column("responsible_team_candidate", Text, nullable=False, default=""),
    Column("fixture_tests", JSON, nullable=False, default=list),
    Column("exception_reason", Text, nullable=False, default=""),
    Column("review_due_at", Text),
    Column("updated_by", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("name", name="custom_rules_name_key"),
)

ownership_reviews = Table(
    "ownership_reviews",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("finding_id", Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True),
    Column("status", Text, nullable=False, default="OPEN"),
    Column("assigned_team", Text, nullable=False, default=""),
    Column("due_at", DateTime(timezone=True)),
    Column("closed_reason", Text, nullable=False, default=""),
    Column("revision", Integer, nullable=False, default=0),
    Column("updated_by", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

connection_check_events = Table(
    "connection_check_events",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("connection_id", Uuid, nullable=False),
    Column("job_id", Uuid, nullable=False),
    Column("source_type", Text, nullable=False, default=""),
    Column("stage", Text, nullable=False, default="REQUESTED"),
    Column("job_status", Text, nullable=False, default="QUEUED"),
    Column("outcome", Text, nullable=False, default="NOT_APPLICABLE"),
    Column("reason_code", Text, nullable=False, default="NONE"),
    Column("provenance", Text, nullable=False, default="JOB_LIFECYCLE"),
    Column("requested_by", Uuid),
    Column("requested_at", DateTime(timezone=True)),
    Column("recorded_at", DateTime(timezone=True), nullable=False, default=_now),
)

scope_catalogs = Table(
    "scope_catalogs",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("connection_id", Uuid, nullable=False),
    Column("snapshot_id", Text, nullable=False, default=""),
    Column("auth_revision", Text, nullable=False, default=""),
    Column("items", JSON, nullable=False, default=list),
    Column("completeness", Text, nullable=False, default="UNKNOWN"),
    Column("reason_code", Text),
    Column("refresh_job_id", Uuid),
    Column("refreshed_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("kind", "connection_id", name="scope_catalogs_connection_key"),
)

catalog_resources = Table(
    "catalog_resources", metadata,
    Column("kind", Text, primary_key=True),
    Column("connection_id", Uuid, primary_key=True),
    Column("resource_id", Text, primary_key=True),
    Column("observed_snapshot", Text, nullable=False),
    Column("name_key", Text, nullable=False),
    Column("updated_key", Text, nullable=False),
    Column("resource_type", Text, nullable=False),
    Column("account_id", Text),
    Column("region", Text),
    Column("item", JSON, nullable=False),
)
Index("catalog_resources_name", catalog_resources.c.kind, catalog_resources.c.connection_id,
      catalog_resources.c.name_key, catalog_resources.c.resource_id)
Index("catalog_resources_updated", catalog_resources.c.kind, catalog_resources.c.connection_id,
      catalog_resources.c.updated_key, catalog_resources.c.resource_id)
Index("catalog_resources_type_region", catalog_resources.c.kind, catalog_resources.c.connection_id,
      catalog_resources.c.resource_type, catalog_resources.c.region)

catalog_indexes = Table(
    "catalog_indexes", metadata,
    Column("kind", Text, primary_key=True),
    Column("connection_id", Uuid, primary_key=True),
    Column("snapshot_id", Text, nullable=False),
)

scope_profiles = Table(
    "scope_profiles",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("connection_id", Uuid, nullable=False),
    Column("name", Text, nullable=False),
    Column("version", Integer, nullable=False, default=1),
    Column("state", Text, nullable=False, default="NO_TARGETS_SELECTED"),
    Column("selected_roots", JSON, nullable=False, default=list),
    Column("excluded_ids", JSON, nullable=False, default=list),
    Column("budgets", JSON, nullable=False, default=dict),
    Column("schedule_minutes", Integer, nullable=False, default=0),
    Column("full_scan_minutes", Integer),
    Column("event_mode", Text, nullable=False, default="DISABLED"),
    Column("change_reason", Text, nullable=False, default=""),
    Column("catalog_snapshot_id", Text, nullable=False, default=""),
    Column("auth_revision", Text, nullable=False, default=""),
    Column("approved_by", Text, nullable=False, default=""),
    Column("approved_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

selection_drafts = Table(
    "selection_drafts",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("connection_id", Uuid, nullable=False),
    Column("catalog_snapshot_id", Text, nullable=False, default=""),
    Column("auth_revision", Text, nullable=False, default=""),
    Column("query", JSON, nullable=False, default=dict),
    Column("resource_ids", JSON, nullable=False, default=list),
    Column("status", Text, nullable=False, default="READY"),
    Column("unknown_remainder", Integer, nullable=False, default=0),
    Column("expires_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

scope_plans = Table(
    "scope_plans",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("connection_id", Uuid, nullable=False),
    Column("profile_id", Uuid, nullable=False),
    Column("profile_version", Integer, nullable=False),
    Column("catalog_snapshot_id", Text, nullable=False, default=""),
    Column("auth_revision", Text, nullable=False, default=""),
    Column("policy_digest", Text, nullable=False, default=""),
    Column("resources", JSON, nullable=False, default=list),
    Column("roots", JSON, nullable=False, default=list),
    Column("known_count", Integer, nullable=False, default=0),
    Column("unresolved_count", Integer, nullable=False, default=0),
    Column("warnings", JSON, nullable=False, default=list),
    Column("executable", Integer, nullable=False, default=0),
    Column("trigger", Text, nullable=False, default="BASELINE"),
    Column("rescan_target", JSON),
    Column("verify", Integer),
    Column("job_id", Uuid),
    Column("expires_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
)

fp_samples = Table(
    "fp_samples",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("scope_kind", Text, nullable=False),
    Column("scope_id", Uuid, nullable=False),
    Column("source_type", Text, nullable=False),
    Column("detector_name", Text, nullable=False),
    Column("credential_type", Text, nullable=False),
    Column("finding_id", Uuid, nullable=False),
    Column("exposure_id", Uuid, nullable=False),
    Column("actor", Text, nullable=False, default=""),
    Column("features", JSON, nullable=False, default=list),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
)

fp_profiles = Table(
    "fp_profiles",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("scope_kind", Text, nullable=False),
    Column("scope_id", Uuid, nullable=False),
    Column("source_type", Text, nullable=False),
    Column("detector_name", Text, nullable=False),
    Column("credential_type", Text, nullable=False),
    Column("sample_count", Integer, nullable=False, default=0),
    Column("distinct_actors", Integer, nullable=False, default=0),
    Column("contradictions", Integer, nullable=False, default=0),
    Column("active", Integer, nullable=False, default=0),
    Column("threshold", Float, nullable=False, default=0.85),
    Column("min_samples", Integer, nullable=False, default=3),
    Column("centroid", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("scope_kind", "scope_id", "source_type", "detector_name", "credential_type",
                     name="fp_profiles_key"),
)

workflow_tickets = Table(
    "workflow_tickets",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("credential_id", Uuid),
    Column("finding_id", Uuid),
    Column("orphan_ref", Uuid),
    Column("provider", Text, nullable=False, default=""),
    Column("credential_type", Text, nullable=False, default=""),
    Column("template_id", Text, nullable=False, default="PUBLIC_EXPOSURE"),
    Column("status", Text, nullable=False, default="OPEN"),
    Column("version", Integer, nullable=False, default=1),
    Column("priority", Text, nullable=False, default="HIGH"),
    Column("service_impact", Text, nullable=False, default="UNKNOWN"),
    Column("responsible_team", Text, nullable=False, default=""),
    Column("owner_id", Uuid),
    Column("review_due_at", DateTime(timezone=True)),
    Column("evidence", JSON, nullable=False, default=list),
    Column("security_review", JSON),
    Column("steps", JSON, nullable=False, default=list),
    Column("playbook", JSON),
    Column("internal_approval", JSON),
    Column("review_digest", Text),
    Column("resolution_basis", Text, nullable=False, default="NOT_RESOLVED"),
    Column("created_by", Uuid),
    Column("updated_by", Uuid),
    Column("assigned_by", Uuid),
    Column("assigned_at", DateTime(timezone=True)),
    Column("resolved_by", Uuid),
    Column("resolved_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

action_plans = Table(
    "action_plans",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("credential_id", Uuid, nullable=False),
    Column("aws_account_id", Text, nullable=False, default=""),
    Column("account_id", Text, nullable=False, default=""),
    Column("user_name", Text, nullable=False, default=""),
    Column("principal_arn", Text, nullable=False, default=""),
    Column("identifier_hint", Text, nullable=False, default=""),
    Column("key_id", Text, nullable=False, default=""),
    Column("action_type", Text, nullable=False),
    Column("status", Text, nullable=False, default="PENDING_APPROVAL"),
    Column("requested_by", Text, nullable=False, default=""),
    Column("requested_at", DateTime(timezone=True)),
    Column("approved_by", Text),
    Column("approved_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True)),
    Column("plan_hash", Text, nullable=False, default=""),
    Column("reason_code", Text, nullable=False, default=""),
    Column("idempotency_key", Text, nullable=False, default=""),
    Column("operational_review", JSON),
    Column("readiness", JSON, nullable=False, default=dict),
    Column("rotation", JSON),
    Column("executed_at", DateTime(timezone=True)),
    Column("provider_write_started_at", DateTime(timezone=True)),
    Column("verified_at", DateTime(timezone=True)),
    Column("safe_error_code", Text),
    Column("result_kind", Text),
    Column("next_step", Text),
    Column("rotation_progress", JSON, nullable=False, default=list),
    Column("workflow_version", Text, nullable=False, default=""),
    Column("adapter_version", Text, nullable=False, default=""),
    Column("policy_revision", Text, nullable=False, default=""),
    Column("semantics_revision", Text, nullable=False, default=""),
    Column("recheck_only", Integer, nullable=False, default=0),
    Column("new_key_id", Text),
    Column("pending_version", Text),
    Column("access_pin", Text),
    Column("target", JSON),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
    UniqueConstraint("idempotency_key", name="action_plans_idempotency_key_key"),
)

# Installation-wide switches an Admin changes from the dashboard (for example
# provider verification). One row per key; the latest writer is recorded.
installation_settings = Table(
    "installation_settings",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", JSON, nullable=False),
    Column("updated_by", Text, nullable=False, default=""),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_now),
)

AUDIT_POSITION_CHECK = "finding_events_chain_seq_positive"

finding_events = Table(
    "finding_events",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("finding_id", Uuid, ForeignKey("findings.id", ondelete="CASCADE")),
    Column("target_type", Text, nullable=False, default="finding"),
    Column("target_id", Uuid),
    Column("actor", Text, nullable=False, default=""),
    Column("event_type", Text, nullable=False),  # ACKNOWLEDGED|RESOLVED|REOPENED|ASSIGNED|CONNECTION_STOPPED
    Column("from_status", Text),
    Column("to_status", Text),
    Column("note", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_now),
    # Tamper evidence (cremore/db/audit_chain.py): the writer's MAC, then the row's place and MAC in the chain.
    Column("entry_mac", Text),
    Column("chain_seq", BigInteger, CheckConstraint("chain_seq IS NULL OR chain_seq >= 1", name=AUDIT_POSITION_CHECK)),
    Column("chain_mac", Text),
)
AUDIT_CHAIN_INDEX = Index("finding_events_chain_seq", finding_events.c.chain_seq, unique=True)
# What the sealer reads each tick: the rows not in the chain yet, oldest first.
AUDIT_UNSEALED_INDEX = Index("finding_events_unsealed", finding_events.c.created_at, finding_events.c.id,
                             postgresql_where=finding_events.c.chain_seq.is_(None),
                             sqlite_where=finding_events.c.chain_seq.is_(None))


from cremore.db.scan_store import register_scan_tables
from cremore.db.task_store import register_task_tables

scan_state_tables = register_scan_tables(metadata)
task_state_tables = register_task_tables(metadata)

from cremore.db.rescore_store import register_rescore_table

rescore_state_table = register_rescore_table(metadata)

from cremore.coverage.store import register_tables as register_coverage_tables

coverage_tables = register_coverage_tables(metadata)

from cremore.operations.coverage_verdicts import register_tables as register_verdict_tables

coverage_verdicts = register_verdict_tables(metadata)

from cremore.coverage.metadata_store import register_tables as register_metadata_tables

coverage_metadata_tables = register_metadata_tables(metadata)

from cremore.identity.leavers import register_tables as register_identity_tables

identity_tables = register_identity_tables(metadata)

from cremore.scanning.changes import register_tables as register_change_tables

change_cursors = register_change_tables(metadata)

from cremore.onboarding.store import register_tables as register_provider_connection_tables

provider_connection_tables = register_provider_connection_tables(metadata)

from cremore.onboarding.session_store import register_table as register_onboarding_session_table

provider_onboarding_sessions = register_onboarding_session_table(metadata)

from cremore.db.annotation_store import register_tables as register_annotation_tables

finding_annotations = register_annotation_tables(metadata)

from cremore.coverage.gcp_store import register_tables as register_gcp_tables

gcp_collection_tables = register_gcp_tables(metadata)

from cremore.coverage.storage_receipts import register_tables as register_storage_receipts

storage_receipt_table = register_storage_receipts(metadata)

# Integration (refactoring + gcp-dashboard-oauth): both branches appended a table
# here; the storage receipt table and the browser-bound GCP OAuth sessions coexist.
from cremore.coverage.gcp_oauth_store import register_tables as register_gcp_oauth_tables

gcp_oauth_sessions = register_gcp_oauth_tables(metadata)

from cremore.governance.ownership import register_tables as register_context_tables

finding_contexts = register_context_tables(metadata)

from cremore.db.people_directory_store import register_tables as register_people_directory_tables

people_directory_tables = register_people_directory_tables(metadata)
