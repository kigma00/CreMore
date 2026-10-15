"""Domain models for the core entities.

These are the business/API representations. Persistence maps them one-to-one
onto the tables in ``cremore/db/schema.py`` (the field names match the columns).
"""

from __future__ import annotations

import enum
import json
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cremore.sources.registry import CONTENT_SCAN_KINDS  # noqa: F401 -- compatibility export


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ExposureStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    MITIGATING = "MITIGATING"
    REMOVED = "REMOVED"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class WorkflowStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"  # analyst judged the match not a credential
    IGNORED = "IGNORED"  # accepted / out of scope, by decision


class CredentialStatus(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    REVOKED = "Revoked"
    EXPIRED = "Expired"


class ConnectionStatus(str, enum.Enum):
    PENDING = "PENDING"    # registered, not yet verified
    ACTIVE = "ACTIVE"      # verified and usable
    DISABLED = "DISABLED"  # turned off by an operator
    ERROR = "ERROR"        # last verification failed


class _Model(BaseModel):
    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class Credential(_Model):
    """A distinct credential identity (deduped by fingerprint + type)."""

    id: uuid.UUID | None = None
    fingerprint: str
    credential_type: str
    identifier: str | None = None
    identifier_hint: str | None = None
    provider: str | None = None
    aws_account_id: uuid.UUID | None = None
    principal_name: str | None = None
    principal_arn: str | None = None
    # How principal_arn was learned: ACTIVE_VERIFICATION | IAM_OWNER_LOOKUP | IAM_INVENTORY.
    principal_arn_source: str | None = None
    business_owner: str | None = None
    team: str | None = None
    service_name: str | None = None
    credential_status: str = CredentialStatus.UNKNOWN.value
    owner_status: str = "UNKNOWN"
    last_used_at: datetime | None = None
    last_used_service: str | None = None
    last_used_region: str | None = None
    credential_created_at: datetime | None = None
    # Last observed-use lookup (CloudTrail event history + IAM last-used);
    # the dashboard's CredentialUsage shape. Never contains key material.
    usage_snapshot: dict | None = None
    # Administrator-declared secret-manager reference (an allowlisted Secrets
    # Manager ARN). A declaration of "possibly stored here", never a value match.
    management_reference: str | None = None
    management_revision: int | None = 0
    management_updated_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class Exposure(_Model):
    """One place a credential was found. AWS-scan and source-scan scopes are
    mutually exclusive (enforced by the DB), so the scan-scope fields are all
    optional here."""

    id: uuid.UUID | None = None
    identity_key: str | None = None
    resource_key: str | None = None
    container_key: str | None = None
    credential_id: uuid.UUID
    source_type: str
    resource_name: str
    location: str
    object_version: str = ""
    line_number: int | None = None
    severity: str = Severity.UNKNOWN.value
    status: str = ExposureStatus.OPEN.value
    resource_arn: str | None = None
    redacted_line: str | None = None
    # AWS-scan scope
    aws_account_id: uuid.UUID | None = None
    first_scan_id: uuid.UUID | None = None
    last_scan_id: uuid.UUID | None = None
    # Source-scan scope (provider-neutral)
    source_connection_id: uuid.UUID | None = None
    first_source_scan_id: uuid.UUID | None = None
    last_source_scan_id: uuid.UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    removed_at: datetime | None = None
    metadata: dict = Field(default_factory=dict)


class Finding(_Model):
    """The credential-level rollup an analyst works with (one per credential)."""

    id: uuid.UUID | None = None
    credential_id: uuid.UUID
    primary_exposure_id: uuid.UUID
    severity: str
    # None is legacy/unobserved. True means locations removed, not key revoked.
    all_locations_removed: bool | None = None
    workflow_status: str = WorkflowStatus.OPEN.value
    assigned_to: str | None = None
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    resolution: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class Connection(_Model):
    """A registered provider integration a scan scope runs against.

    A connection never stores the credential itself: ``config`` holds only
    non-secret scope (bucket, owner/repo, region, account id) and ``secret_ref``
    is a pointer into the secret store the worker resolves at run time. The
    mapping layer rejects a ``config`` that carries secret-looking keys.
    """

    id: uuid.UUID | None = None
    provider: str  # aws | github | notion
    name: str
    status: str = ConnectionStatus.PENDING.value
    config: dict = Field(default_factory=dict)
    secret_ref: str | None = None
    last_error: str | None = None
    last_verified_at: datetime | None = None
    # Outcome of the last credential check (status, owner/identity, scopes,
    # checked_at, error code). Never the credential itself.
    credential_evidence: dict | None = None
    # Last read of the provider's own secret-scanning alerts (GitHub). Alert
    # metadata and counts only, never the secret the alert is about.
    secret_scanning: dict | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AwsAccount(_Model):
    """A connected AWS account the platform scans and inventories."""

    id: uuid.UUID | None = None
    account_id: str
    name: str
    environment: str = ""
    scanner_role_arn: str | None = None
    remediation_role_arn: str | None = None
    enabled: bool = True
    validation_status: str = "PENDING"  # PENDING | VALID | INVALID
    # Unique per-account value the member role's trust policy requires as the
    # STS ExternalId (confused-deputy guard). An identifier, not a secret.
    external_id: str | None = None
    # Administrator's non-secret declaration (product/auth/environment) as the
    # dashboard records it; never observed evidence.
    declaration: dict | None = None
    # Safe reason code and time of the last check run by the worker, which is
    # the process that actually assumes the role when scanning.
    validation_detail: str | None = None
    validated_at: datetime | None = None
    # How CreMore reaches the account: ROLE (member scanner/remediation roles),
    # RUNTIME_IDENTITY (the approved identity's own account, used directly), or
    # SSO_PERMISSION_SET (IAM Identity Center vends this account's credentials
    # for the operator's own assignment; nothing is deployed, scanning only).
    access: str = "ROLE"
    # SSO_PERMISSION_SET only: the permission set name assigned in this account.
    # It is what sso:GetRoleCredentials is called with and what the assumed role
    # name is checked against; never an ARN.
    sso_role_name: str | None = None
    # Per purpose, bumped when that purpose's role ARN, the ExternalId or the
    # access mode change; validation results are stored with
    # "<revision>:<approval_revision>" and only count while both still match
    # (cremore/aws_access.py).
    access_revision: int = 1
    remediation_access_revision: int = 1
    validation_key: str | None = None
    remediation_validation_status: str = "PENDING"
    remediation_validation_detail: str | None = None
    remediation_validated_at: datetime | None = None
    remediation_validation_key: str | None = None
    # MANUAL, ORGANIZATION when an organization sync registered it, or SSO when
    # an Identity Center assignment sweep did. The facts below come from the last
    # complete sync of whichever it was; blocks are computed from them, and
    # org_present means "still listed" for both sweeps (cremore/aws_access.py).
    source: str = "MANUAL"
    org_state: str | None = None
    org_present: bool | None = None
    in_deployment_scope: bool | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("access", "access_revision", "remediation_access_revision", "remediation_validation_status", "source",
                     mode="before")
    @classmethod
    def _column_default(cls, value, info):
        # Rows written before these nullable columns existed read back as NULL.
        return cls.model_fields[info.field_name].default if value is None else value


class GovernanceReview(_Model):
    """An ownership/management review opened against a finding."""

    id: uuid.UUID | None = None
    finding_id: uuid.UUID
    kind: str = "OWNERSHIP"  # OWNERSHIP | MANAGEMENT | ACCESS
    status: str = "OPEN"  # OPEN | ACKNOWLEDGED | RESOLVED
    assignee: str | None = None
    question: str = ""
    response: str | None = None
    created_by: str = ""
    created_at: datetime | None = None
    resolved_at: datetime | None = None


class RotationJob(_Model):
    """An approved AWS key rotation job (PREPARE/PUBLISH two-phase)."""

    id: uuid.UUID | None = None
    credential_id: uuid.UUID
    status: str = "REQUESTED"  # REQUESTED | PREPARED | PUBLISHED | FAILED
    phase: str = "PREPARE"  # PREPARE | PUBLISH
    requested_by: str = ""
    approved_by: str | None = None
    error: str | None = None
    # The bound rotation plan (identifiers only — never key material).
    secret_arn: str = ""
    user_name: str = ""
    account_id: str = ""
    old_key_id: str = ""
    expected_current_version: str = ""
    new_key_id: str | None = None
    pending_version: str | None = None
    access_pin: str | None = None  # authorization PREPARE ran under; PUBLISH requires it
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ManagementAction(_Model):
    """A requested, approval-gated management action against a credential."""

    id: uuid.UUID | None = None
    finding_id: uuid.UUID
    action_type: str  # DISABLE | ROTATE | ACKNOWLEDGE_OWNER | ...
    status: str = "PENDING"  # PENDING | CONFIRMED | EXECUTED | REJECTED
    requested_by: str = ""
    confirmed_by: str | None = None
    note: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FindingEvent(_Model):
    """One entry in the installation's audit trail (who did what, and when).

    It began as a finding's trail and still is one for most events, but a
    connection being stopped is the same kind of fact: an operator acted, and a
    reader needs to see it later. ``target_type``/``target_id`` name what was
    acted on; ``finding_id`` is set only when that target is a finding, so the
    finding-scoped queries stay exactly as narrow as they were.
    """

    id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    target_type: str = "finding"
    target_id: uuid.UUID | None = None
    actor: str = ""  # subject id of the operator
    event_type: str = ""  # ACKNOWLEDGED | RESOLVED | REOPENED | ASSIGNED
    from_status: str | None = None
    to_status: str | None = None
    note: str | None = None
    created_at: datetime | None = None


class CustomRule(_Model):
    """An operator-authored regex detector.

    Matches are reported under the synthetic ``custom`` provider with the
    operator's severity — they are never presented as provider-verified
    credentials. The pattern is validated to be RE2-safe and non-trivial.
    """

    id: uuid.UUID | None = None
    name: str
    description: str = ""
    enabled: bool = True
    rule_type: str = "regex"
    keywords: list[str] = Field(default_factory=list)
    pattern: str
    severity: str = "HIGH"  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    revision: int = 1
    scope_sources: list[str] = Field(default_factory=list)  # s3 | github | notion | inline
    include_globs: list[str] = Field(default_factory=list)  # fnmatch on the location
    exclude_globs: list[str] = Field(default_factory=list)
    exclude_words: list[str] = Field(default_factory=list)  # in the matched line -> skip
    provider_candidates: list[str] = Field(default_factory=list)
    content_kinds: list[str] = Field(default_factory=list)
    category: str | None = None  # what the value is: token | apikey | secret | ... (the rule list's Type)
    responsible_team_candidate: str = ""
    fixture_tests: list[dict] = Field(default_factory=list)  # [{id, expected}]
    exception_reason: str = ""
    review_due_at: str | None = None
    updated_by: str | None = None  # set by the server from the actor that created or changed the rule
    created_at: datetime | None = None
    updated_at: datetime | None = None


OWNERSHIP_REVIEW_STATUSES = ("OPEN", "IN_PROGRESS", "WAITING_OWNER", "CLOSED")


class OwnershipReview(_Model):
    """Who is responsible for a finding, and where that investigation stands."""

    id: uuid.UUID | None = None
    finding_id: uuid.UUID
    status: str = "OPEN"  # OPEN | IN_PROGRESS | WAITING_OWNER | CLOSED
    assigned_team: str = ""
    due_at: datetime | None = None
    closed_reason: str = ""  # RESPONSIBLE_TEAM_CONFIRMED | CREDENTIAL_RETIRED | NOT_ACTIONABLE
    revision: int = 0  # optimistic-concurrency token the dashboard sends back
    updated_by: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def audit_event(self, previous_status: str | None, actor: str) -> FindingEvent:
        """The audit trail's record of this review as saved: its team (quoted, so no team name reads as another
        field), due date and closing reason."""
        due = self.due_at.isoformat() if self.due_at else "-"
        note = (f"team={json.dumps(self.assigned_team or '', ensure_ascii=False)} due={due}"
                + (f" reason={self.closed_reason}" if self.closed_reason else ""))
        return FindingEvent(finding_id=self.finding_id, target_id=self.finding_id, actor=actor,
                            event_type="OWNERSHIP_REVIEW_UPDATED", from_status=previous_status, to_status=self.status, note=note)


class ConnectionCheckEvent(_Model):
    """One append-only entry in a connection's credential-check ledger.

    Recorded with the job's state changes (requested, claimed, ended); the
    HTTP send itself is not captured. ``outcome`` is the check result only at
    the terminal stage.
    """

    id: uuid.UUID | None = None
    connection_id: uuid.UUID
    job_id: uuid.UUID
    source_type: str = ""
    stage: str = "REQUESTED"  # REQUESTED | CLAIMED_FOR_CHECK | TERMINAL
    job_status: str = "QUEUED"  # QUEUED | RUNNING | COMPLETED | FAILED | CANCELLED
    outcome: str = "NOT_APPLICABLE"  # NOT_APPLICABLE | ACTIVE | RESTRICTED | REJECTED | INDETERMINATE | UNCERTAIN | NOT_DISPATCHED
    reason_code: str = "NONE"  # NONE | CHECK_RESULT | JOB_FAILED | JOB_CANCELLED
    provenance: str = "JOB_LIFECYCLE"
    requested_by: uuid.UUID | None = None
    requested_at: datetime | None = None
    recorded_at: datetime | None = None


class FPSample(_Model):
    """One confirmed false positive, reduced to redacted path / line-shape
    features. Never the match, identifier, hint or fingerprint."""

    id: uuid.UUID | None = None
    scope_kind: str  # aws | source
    scope_id: uuid.UUID
    source_type: str
    detector_name: str
    credential_type: str
    finding_id: uuid.UUID
    exposure_id: uuid.UUID
    actor: str = ""
    features: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class FPProfile(_Model):
    """A per-scope learned false-positive profile (the dashboard's LearnedFPProfile)."""

    id: uuid.UUID | None = None
    scope_kind: str
    scope_id: uuid.UUID
    source_type: str
    detector_name: str
    credential_type: str
    sample_count: int = 0
    distinct_actors: int = 0
    contradictions: int = 0
    active: bool = False
    threshold: float = 0.85
    min_samples: int = 3
    centroid: dict = Field(default_factory=dict)  # feature -> share of samples carrying it
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WorkflowTicket(_Model):
    """An internal response ticket: who reviews what, by when, against a
    playbook checklist. Operator declarations only — never a provider action,
    never proof of revocation or workload adoption."""

    id: uuid.UUID | None = None
    # A ticket is about a finding (credential_id and finding_id), or about a departed
    # owner's credential (orphan_ref, cremore.identity.leavers), which may never have
    # been exposed and so has no finding.
    credential_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    orphan_ref: uuid.UUID | None = None
    provider: str = ""
    credential_type: str = ""
    template_id: str = "PUBLIC_EXPOSURE"
    status: str = "OPEN"  # OPEN | IN_PROGRESS | WAITING_OWNER | WAITING_APPROVAL | NEEDS_ATTENTION | RESOLVED
    version: int = 1
    priority: str = "HIGH"  # CRITICAL | HIGH | MEDIUM | LOW
    service_impact: str = "UNKNOWN"  # UNKNOWN | NONE | LIMITED | SIGNIFICANT
    responsible_team: str = ""
    owner_id: uuid.UUID | None = None
    review_due_at: datetime | None = None
    evidence: list[dict] = Field(default_factory=list)  # [{kind, id}]
    security_review: dict | None = None
    steps: list[dict] = Field(default_factory=list)  # [{code, status, reviewed_by?, reviewed_at?}]
    playbook: dict | None = None  # immutable snapshot for CUSTOM templates
    internal_approval: dict | None = None
    review_digest: str | None = None
    resolution_basis: str = "NOT_RESOLVED"
    created_by: uuid.UUID | None = None
    updated_by: uuid.UUID | None = None
    assigned_by: uuid.UUID | None = None
    assigned_at: datetime | None = None
    resolved_by: uuid.UUID | None = None
    resolved_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


ACTION_PLAN_UNRESOLVED = ("PENDING_APPROVAL", "APPROVED", "QUEUED", "EXECUTING", "OUTCOME_UNKNOWN")
ACTION_PLAN_STATUSES = (*ACTION_PLAN_UNRESOLVED, "VERIFIED", "FAILED", "CANCELLED", "EXPIRED")


class ActionPlan(_Model):
    """An approval-bound credential operation: an AWS IAM key (disable, delete, rotation phase), or another
    provider's credential by the id its own list gives (``target``, cremore.remediation.provider_actions).

    Approval and execution are bound to ``plan_hash`` — a digest of the exact
    target and plan content — so nothing can be approved and then changed.
    Every provider write is preceded by ``provider_write_started_at`` and
    followed by a read-back; a write whose outcome could not be confirmed is
    ``OUTCOME_UNKNOWN`` and is only ever *rechecked*, never retried.
    """

    id: uuid.UUID | None = None
    # The target a plan reserves: a discovered credential's id, or for ``target`` plans a key derived from the
    # provider's own reference (the same credential, however many inventories list it).
    credential_id: uuid.UUID
    aws_account_id: str = ""  # registered AwsAccount record id, when known
    account_id: str = ""
    user_name: str = ""
    principal_arn: str = ""
    identifier_hint: str = ""
    key_id: str = ""  # the access key id (an identifier, not a secret); server-side only
    action_type: str
    status: str = "PENDING_APPROVAL"
    requested_by: str = ""
    requested_at: datetime | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    plan_hash: str = ""
    reason_code: str = ""
    idempotency_key: str = ""
    operational_review: dict | None = None
    readiness: dict = Field(default_factory=dict)
    rotation: dict | None = None
    executed_at: datetime | None = None
    provider_write_started_at: datetime | None = None
    verified_at: datetime | None = None
    safe_error_code: str | None = None
    result_kind: str | None = None
    next_step: str | None = None
    rotation_progress: list[dict] = Field(default_factory=list)
    workflow_version: str = ""
    adapter_version: str = ""
    policy_revision: str = ""
    semantics_revision: str = ""
    recheck_only: bool = False
    # rotation phase outputs (identifiers only)
    new_key_id: str | None = None
    pending_version: str | None = None
    access_pin: str | None = None  # PREPARE plans: authorization the successor was prepared under
    # Another provider's credential: {provider, entity_id, object_id, origin, tenant, reference, hint, connection_id}.
    target: dict | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def reserves_target(self, now: datetime) -> bool:
        return self.status in ACTION_PLAN_UNRESOLVED and not (
            self.status in ("PENDING_APPROVAL", "APPROVED") and self.expires_at and self.expires_at <= now
        )


class ScanRun(_Model):
    """A scan execution."""

    id: uuid.UUID | None = None
    trigger_type: str = "MANUAL"
    status: str = "QUEUED"
    connection_id: uuid.UUID | None = None
    resources_succeeded: int = 0
    resources_failed: int = 0
    detector_succeeded: int | None = None
    engine_name: str = ""
    engine_version: str = ""
    created_at: datetime | None = None


class JobStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLING = "CANCELLING"  # stop requested while running; no new work, no late results
    CANCELLED = "CANCELLED"  # withdrawn while queued, or stopped after CANCELLING


# Jobs that read provider content. Only one of them may be active at a time in an
# installation; checks, catalog refreshes and role checks are not limited.
# A content scan holds the installation's single slot in any of these states.
# The slot follows the job, not a heartbeat: a task parked for an AWS sign-in
# returns to QUEUED while its job stays RUNNING and keeps the slot.
ACTIVE_JOB_STATUSES = ("QUEUED", "RUNNING", "CANCELLING")


class ScanBusy(RuntimeError):
    """A content scan was requested while another one holds the slot."""

    def __init__(self, active: ScanJob | None):
        super().__init__("ALREADY_SCANNING")
        self.active = active


class ScanJob(_Model):
    """A queued scan the worker will run."""

    id: uuid.UUID | None = None
    kind: str  # inline | s3 | github | notion
    status: str = JobStatus.QUEUED.value
    payload: dict = Field(default_factory=dict)
    connection_id: uuid.UUID | None = None
    objects: int = 0
    findings: int = 0
    # Listed but unreadable objects; > 0 marks a SUCCEEDED run as partial.
    objects_failed: int | None = 0
    # Observed coverage counters of a scoped run (attempted/succeeded/failed/
    # skipped/bytes/requests, budget stop reason). Additive, nullable.
    coverage: dict | None = None
    error: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ScopeCatalog(_Model):
    """The metadata catalog of one connection's scannable resources.

    One row per (kind, connection_id). ``items`` are the dashboard's
    ScopeResource dicts as the last metadata refresh observed them; listing a
    resource here never approves scanning its content.
    """

    id: uuid.UUID | None = None
    kind: str  # aws | source
    connection_id: uuid.UUID
    snapshot_id: str = ""  # "" until the first refresh completed
    auth_revision: str = ""
    items: list[dict] = Field(default_factory=list)
    completeness: str = "UNKNOWN"  # COMPLETE | PARTIAL | UNKNOWN
    reason_code: str | None = None
    refresh_job_id: uuid.UUID | None = None
    refreshed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ScopeProfile(_Model):
    """An Admin-approved, versioned selection of exact resources to scan."""

    id: uuid.UUID | None = None
    kind: str
    connection_id: uuid.UUID
    name: str
    version: int = 1
    state: str = "NO_TARGETS_SELECTED"  # NO_TARGETS_SELECTED | READY | NEEDS_SCOPE_REVIEW | PAUSED
    selected_roots: list[dict] = Field(default_factory=list)
    excluded_ids: list[str] = Field(default_factory=list)
    budgets: dict = Field(default_factory=dict)
    schedule_minutes: int = 0
    full_scan_minutes: int | None = None  # None keeps legacy daily reconciliation; 0 disables it.
    event_mode: str = "DISABLED"
    change_reason: str = ""
    catalog_snapshot_id: str = ""
    auth_revision: str = ""
    approved_by: str = ""
    approved_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SelectionDraft(_Model):
    """A frozen resolution of a catalog query into exact resource ids."""

    id: uuid.UUID | None = None
    kind: str
    connection_id: uuid.UUID
    catalog_snapshot_id: str = ""
    auth_revision: str = ""
    query: dict = Field(default_factory=dict)
    resource_ids: list[str] = Field(default_factory=list)
    status: str = "READY"  # QUEUED | PREPARING | READY | CANCELLED | FAILED | EXPIRED
    unknown_remainder: bool = False
    expires_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ScopePlan(_Model):
    """A fixed, expiring preview of exactly what a run would read."""

    id: uuid.UUID | None = None
    kind: str
    connection_id: uuid.UUID
    profile_id: uuid.UUID
    profile_version: int
    catalog_snapshot_id: str = ""
    auth_revision: str = ""
    policy_digest: str = ""
    resources: list[dict] = Field(default_factory=list)
    roots: list[dict] = Field(default_factory=list)  # effective per-resource selections
    known_count: int = 0
    unresolved_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    executable: bool = False
    trigger: str = "BASELINE"  # BASELINE | RESCAN
    rescan_target: dict | None = None
    verify: bool | None = None
    job_id: uuid.UUID | None = None  # set once a run consumed the plan
    expires_at: datetime | None = None
    created_at: datetime | None = None
