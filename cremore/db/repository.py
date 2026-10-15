"""Repository protocol and an in-memory implementation.

The protocol is exactly the persistence surface the scan pipeline and API need.
Deduplication mirrors the SQL unique constraints:

* credentials  UNIQUE(fingerprint, credential_type)
* exposures    UNIQUE(credential_id, aws_account_id, source_type, resource_name, location, object_version)
* findings     one per credential
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import wraps
from threading import RLock
from typing import Protocol

from cremore.db import audit_chain
from cremore.db.scan_state import (
    SEVERITY_RANK,
    exposure_container_key,
    exposure_identity,
    exposure_location,
    exposure_resource_key,
    observation_metadata,
    rollup_changes,
)
from cremore.domain.models import (
    ACTIVE_JOB_STATUSES,
    CONTENT_SCAN_KINDS,
    ActionPlan,
    AwsAccount,
    Connection,
    ConnectionCheckEvent,
    Credential,
    CustomRule,
    Exposure,
    Finding,
    FindingEvent,
    FPProfile,
    FPSample,
    GovernanceReview,
    JobStatus,
    ManagementAction,
    OwnershipReview,
    RotationJob,
    ScanJob,
    ScopeCatalog,
    ScopePlan,
    ScopeProfile,
    SelectionDraft,
    WorkflowTicket,
)
from cremore.siem.events import (
    audit_action,
    export_audit,
    finding_created,
    finding_exposure,
    finding_updated,
    stamped,
)

INSTALLATION_KEY = "siem.installation"


def _now() -> datetime:
    return datetime.now(UTC)


# A stop request wins over any later completion or failure of the same job.
_STOPPED = (JobStatus.CANCELLING.value, JobStatus.CANCELLED.value)


def job_lane(kind: str, payload: dict | None) -> str:
    """The lane of a content job in its connection's execution slot (scan_jobs.lane).

    A change event's run gets its own lane, so it does not wait out a long sweep of the same connection; the
    runtime's per-root task locks still keep the two off one bucket, repository or page at once. The mode is read
    the way the runtime plans it (absent means BASELINE): a BASELINE reread, which a change feed asks for after a
    history rewrite, scans whole roots like a sweep and waits in that lane.
    """
    payload = payload or {}
    event = (kind == "scope" and payload.get("trigger") == "EVENT"
             and str(payload.get("mode", "BASELINE")).upper() != "BASELINE")
    return "event" if event else "sweep"


def receipt_reopens(key: str, begins: datetime, status: str | None, slot_receipt: str | None, requested_by: str | None,
                    created_at: datetime | None) -> bool:
    """Whether a schedule slot's receipt ``key`` no longer answers its slot (which began at ``begins``): it names another
    run the slot was merged into (an Admin's, or a scheduled run of another slot) that then ended CANCELLED or FAILED.
    A run the schedule queued for this slot consumes it however it ended, so an operator's cancel still skips that slot:
    its payload's ``slot_receipt`` is ``key``, or it is a scheduled run from before that field existed, queued within
    the slot (one queued in an earlier slot is that slot's run)."""
    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)  # SQLite drops tz
    own = slot_receipt == key or (slot_receipt is None and requested_by == "schedule"
                                  and created_at is not None and created_at >= begins)
    return status in (JobStatus.CANCELLED.value, JobStatus.FAILED.value) and not own


_UNSEALED = {"entry_mac": None, "chain_seq": None, "chain_mac": None}


def _synchronized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call


class Repository(Protocol):
    def get_setting(self, key: str) -> dict | None: ...
    def list_settings(self, prefix: str) -> list[dict]: ...
    def claim_slot(self, key: str, slot: int, updated_by: str) -> bool: ...
    def delete_settings_before(self, prefix: str, cutoff: datetime) -> int: ...
    def record_siem_event(self, event: dict, audit: FindingEvent | None = None) -> bool: ...
    def put_setting(self, key: str, value: dict, updated_by: str) -> dict: ...
    def put_settings(self, values: dict[str, dict], updated_by: str) -> dict[str, dict]: ...
    def put_revisioned_setting(self, key: str, value: dict, updated_by: str) -> dict: ...
    def upsert_credential(self, credential: Credential) -> Credential: ...
    def upsert_exposure(self, exposure: Exposure) -> Exposure: ...
    def upsert_finding(self, credential_id: uuid.UUID, primary_exposure_id: uuid.UUID, severity: str) -> Finding: ...
    def get_finding_for_credential(self, credential_id: uuid.UUID) -> Finding | None: ...
    def count_exposures_for_credential(self, credential_id: uuid.UUID) -> int: ...
    def best_exposure_for_credential(self, credential_id: uuid.UUID, preferred_id: uuid.UUID | None = None) -> tuple[str, uuid.UUID | None]: ...
    def repair_finding_rollup(self, credential_id: uuid.UUID) -> Finding | None: ...
    def finish_credential_check(self, job: ScanJob, connection_changes: dict, event: ConnectionCheckEvent, error: str | None = None) -> ScanJob: ...
    def set_exposure_severity(self, exposure_id: uuid.UUID, severity: str, *, metadata: dict | None = None) -> None: ...
    def get_credential(self, credential_id: uuid.UUID) -> Credential | None: ...
    def get_credential_by_fingerprint(self, fingerprint: str, credential_type: str) -> Credential | None: ...
    def find_component_pairs(self, credential_type: str, fingerprint: str, limit: int) -> list[Exposure]: ...
    def update_credential(self, credential_id: uuid.UUID, **changes) -> Credential | None: ...
    def list_findings(self, *, limit: int | None = None, after: uuid.UUID | None = None) -> list[Finding]: ...
    def finding_stats(self) -> dict: ...

    def search_findings(self, needle: str, limit: int) -> tuple[list[dict], int]: ...
    def search_connections(self, needle: str, limit: int) -> tuple[list[dict], int]: ...
    def search_aws_accounts(self, needle: str, limit: int) -> tuple[list[dict], int]: ...
    def search_assets(self, needle: str, limit: int) -> tuple[list[dict], int, bool]: ...
    def get_finding(self, finding_id: uuid.UUID) -> Finding | None: ...
    def update_finding_status(self, finding_id: uuid.UUID, workflow_status: str, resolution: str | None = None, *, expected_updated_at=None, expected_status=None, expected_resolution=None) -> Finding | None: ...
    def assign_finding(self, finding_id: uuid.UUID, assignee: str | None) -> Finding | None: ...
    def record_finding_event(self, event: FindingEvent) -> FindingEvent: ...
    def list_finding_events(self, finding_id: uuid.UUID) -> list[FindingEvent]: ...
    # the audit trail's hash chain (cremore/db/audit_chain.py)
    def seal_audit(self, secret: bytes, limit: int = 1000, expected: tuple[int, str] | None = None) -> dict: ...
    def audit_chain_page(self, after_seq: int = 0, limit: int = 2000) -> list[dict]: ...
    def unsealed_audit(self, limit: int = 10000) -> list[dict]: ...
    def audit_rows_outside_chain(self, limit: int = 100) -> list[dict]: ...
    def audit_chain_rows(self) -> list[dict]: ...
    def audit_macs_at(self, seqs: list[int]) -> dict[int, str | None]: ...
    def exposures_for_credential(self, credential_id: uuid.UUID) -> list[Exposure]: ...
    def findings_with_exposures(self, finding_ids: list[uuid.UUID], *, exposure_limit: int | None = None) -> list[tuple[Finding, Credential | None, list[Exposure]]]: ...
    def exposures_for_connection(self, connection_id: uuid.UUID) -> list[Exposure]: ...
    def exposures_for_root(self, connection_id: uuid.UUID, source_type: str, resource_name: str, *, page_id: str | None = None) -> list[Exposure]: ...
    def exposures_for_resource(self, connection_id: uuid.UUID, source_type: str, resource_name: str, location: str, *, page_id: str | None = None, epoch: str | int | None = None) -> list[Exposure]: ...
    def mark_exposure_removed(self, exposure_id: uuid.UUID) -> None: ...
    def mark_exposure_seen(self, exposure_id: uuid.UUID) -> None: ...
    def enqueue_job(self, job: ScanJob) -> ScanJob: ...
    def claim_next_job(self, *, execution_role="mixed") -> ScanJob | None: ...
    def complete_job(self, job_id: uuid.UUID, objects: int, findings: int, objects_failed: int = 0,
                     coverage: dict | None = None) -> None: ...
    def fail_job(self, job_id: uuid.UUID, error: str) -> None: ...
    def get_job(self, job_id: uuid.UUID) -> ScanJob | None: ...
    def list_jobs(self, limit: int = 100) -> list[ScanJob]: ...
    def job_queue_summary(self) -> dict: ...
    def latest_connection_jobs(self, kinds: tuple[str, ...], status: str) -> dict[uuid.UUID, ScanJob]: ...
    def cancel_job(self, job_id: uuid.UUID) -> ScanJob | None: ...
    def request_job_cancel(self, job_id: uuid.UUID) -> ScanJob | None: ...
    def finish_cancelled_job(self, job_id: uuid.UUID, coverage: dict | None = None) -> None: ...
    def active_content_job(self) -> ScanJob | None: ...
    def list_events(self, limit: int = 200) -> list[FindingEvent]: ...
    # enterprise entities (AWS accounts, governance, rotation, management)
    def create_aws_account(self, account: AwsAccount) -> AwsAccount: ...
    def list_aws_accounts(self) -> list[AwsAccount]: ...
    def get_aws_account(self, account_id: uuid.UUID, *, for_update: bool = False) -> AwsAccount | None: ...
    def update_aws_account(self, account_id: uuid.UUID, **changes) -> AwsAccount | None: ...
    def update_aws_account_if_revision(self, account_id: uuid.UUID, revision_field: str, revision: int, **changes) -> AwsAccount | None: ...
    def create_review(self, review: GovernanceReview) -> GovernanceReview: ...
    def list_reviews(self, *, limit: int | None = None, after: uuid.UUID | None = None) -> list[GovernanceReview]: ...
    def get_review(self, review_id: uuid.UUID) -> GovernanceReview | None: ...
    def update_review(self, review_id: uuid.UUID, **changes) -> GovernanceReview | None: ...
    def create_rotation_job(self, job: RotationJob) -> RotationJob: ...
    def list_rotation_jobs(self, *, limit: int | None = None, after: uuid.UUID | None = None) -> list[RotationJob]: ...
    def get_rotation_job(self, job_id: uuid.UUID) -> RotationJob | None: ...
    def update_rotation_job(self, job_id: uuid.UUID, **changes) -> RotationJob | None: ...
    def create_management_action(self, action: ManagementAction,
                                 audit: Callable[[ManagementAction], FindingEvent] | None = None) -> ManagementAction: ...
    def list_management_actions(self, *, limit: int | None = None, after: uuid.UUID | None = None) -> list[ManagementAction]: ...
    def get_management_action(self, action_id: uuid.UUID) -> ManagementAction | None: ...
    def update_management_action(self, action_id: uuid.UUID, *, expected_status: str | None = None,
                                 audit: FindingEvent | None = None, **changes) -> ManagementAction | None: ...
    def create_connection(self, connection: Connection) -> Connection: ...
    def get_connection(self, connection_id: uuid.UUID, *, for_update: bool = False) -> Connection | None: ...
    def list_connections(self) -> list[Connection]: ...
    def update_connection(self, connection_id: uuid.UUID, *, expected_status: str | None = None, **changes) -> Connection | None: ...
    # operator rules and ownership reviews
    def create_rule(self, rule: CustomRule) -> CustomRule: ...
    def list_rules(self) -> list[CustomRule]: ...
    def get_rule(self, rule_id: uuid.UUID) -> CustomRule | None: ...
    def update_rule(self, rule_id: uuid.UUID, **changes) -> CustomRule | None: ...
    def delete_rule(self, rule_id: uuid.UUID) -> bool: ...
    def get_ownership_review(self, finding_id: uuid.UUID) -> OwnershipReview | None: ...
    def save_ownership_review(self, review: OwnershipReview) -> OwnershipReview: ...
    def save_ownership_reviews(self, reviews: list[OwnershipReview], *, audit_actor: str | None) -> list[OwnershipReview] | None: ...
    # approval-bound IAM key action plans
    def create_action_plan(self, plan: ActionPlan, audit: FindingEvent | None = None) -> ActionPlan: ...
    def list_action_plans(self, credential_id: uuid.UUID | None = None, limit: int = 500) -> list[ActionPlan]: ...
    def get_action_plan(self, plan_id: uuid.UUID) -> ActionPlan | None: ...
    def find_action_plan(self, idempotency_key: str) -> ActionPlan | None: ...
    def update_action_plan(self, plan_id: uuid.UUID, *, expected_status: str | None = None,
                           audit: FindingEvent | None = None, **changes) -> ActionPlan | None: ...
    # connection credential-check ledger (append-only)
    def record_check_event(self, event: ConnectionCheckEvent) -> ConnectionCheckEvent: ...
    def list_check_events(self, connection_id: uuid.UUID) -> list[ConnectionCheckEvent]: ...
    # scan scope: resource catalog, approved profiles, drafts, plans
    def save_catalog(self, catalog: ScopeCatalog) -> ScopeCatalog: ...
    def get_catalog(self, kind: str, connection_id: uuid.UUID) -> ScopeCatalog | None: ...
    def create_scope_profile(self, profile: ScopeProfile) -> ScopeProfile: ...
    def list_scope_profiles(self, kind: str, connection_id: uuid.UUID) -> list[ScopeProfile]: ...
    def get_scope_profile(self, profile_id: uuid.UUID) -> ScopeProfile | None: ...
    def update_scope_profile(self, profile_id: uuid.UUID, *, expected_version: int | None = None, **changes) -> ScopeProfile | None: ...
    def create_draft(self, draft: SelectionDraft) -> SelectionDraft: ...
    def get_draft(self, draft_id: uuid.UUID) -> SelectionDraft | None: ...
    def update_draft(self, draft_id: uuid.UUID, **changes) -> SelectionDraft | None: ...
    def create_plan(self, plan: ScopePlan) -> ScopePlan: ...
    def get_plan(self, plan_id: uuid.UUID) -> ScopePlan | None: ...
    def update_plan(self, plan_id: uuid.UUID, **changes) -> ScopePlan | None: ...
    def consume_scope_plan(self, plan_id: uuid.UUID, expected_version: int, job: ScanJob) -> tuple[ScanJob, bool]: ...
    def enqueue_triggered_scope(self, plan: ScopePlan, job: ScanJob, receipt_key: str,
                                replaces: uuid.UUID | None = None) -> tuple[ScanJob, bool]: ...
    def coalesce_scheduled_scope(self, receipt_key: str, profile: ScopeProfile, auth_revision: str,
                                 modes: tuple[str, ...], since: datetime,
                                 replaces: uuid.UUID | None = None) -> ScanJob | None: ...
    def list_scheduled_profiles(self, full_scan_default: int = 0) -> list[ScopeProfile]: ...
    def list_scope_profiles_page(self, cursor: str | None = None, limit: int = 100) -> tuple[list[ScopeProfile], str | None]: ...
    def prune_trigger_receipts(self, before: datetime, limit: int = 10000) -> int: ...
    # (answered, replaces) for the slot that began at ``begins``: replaces is the ended run a reopened slot's receipt
    # still names, for the swap
    def slot_receipt_state(self, key: str, begins: datetime) -> tuple[bool, uuid.UUID | None]: ...
    # whether the receipt answers that slot and the run it names has ended (in any status, or is gone)
    def slot_run_ended(self, key: str, begins: datetime) -> bool: ...
    def active_scope_runs(self, connection_id: uuid.UUID, profile_id: str, profile_version: int) -> list[ScanJob]: ...
    # learned false-positive profiles (key = scope_kind, scope_id, source_type, detector_name, credential_type)
    def create_fp_sample(self, sample: FPSample) -> FPSample: ...
    def list_fp_samples(self, **key) -> list[FPSample]: ...
    def delete_fp_samples(self, **key) -> int: ...
    def get_fp_profile(self, **key) -> FPProfile | None: ...
    def get_fp_profile_by_id(self, profile_id: uuid.UUID) -> FPProfile | None: ...
    def save_fp_profile(self, profile: FPProfile) -> FPProfile: ...
    def list_fp_profiles(self) -> list[FPProfile]: ...
    # internal workflow tickets
    def create_ticket(self, ticket: WorkflowTicket) -> WorkflowTicket: ...
    def list_tickets(self, credential_id: uuid.UUID | None = None, *, limit: int | None = None, offset: int = 0) -> list[WorkflowTicket]: ...
    def get_ticket(self, ticket_id: uuid.UUID) -> WorkflowTicket | None: ...
    def update_ticket(self, ticket_id: uuid.UUID, *, expected_version: int | None = None, **changes) -> WorkflowTicket | None: ...


def _connection_search_row(conn) -> dict:
    """One connection as a search hit, with the scope it actually covers."""
    config = conn.config or {}
    scope = (config.get("bucket") or config.get("org")
             or "/".join(v for v in (config.get("owner"), config.get("repo")) if v) or "")
    provider = (conn.provider or "").lower()
    haystack = " ".join(str(v) for v in (conn.name, provider, scope, conn.id,
                                         *config.values())).lower()
    return {"kind": "connection", "id": str(conn.id), "label": conn.name or str(conn.id),
            "provider": provider, "context": scope, "detail": conn.status,
            "_haystack": haystack}


def _aws_account_search_row(account) -> dict:
    """One AWS account as a search hit. "aws" belongs in the haystack: an account
    named after its own number is still an AWS object."""
    haystack = " ".join(str(v) for v in ("aws", account.name, account.account_id,
                                         account.environment, account.id)).lower()
    return {"kind": "aws_account", "id": str(account.id),
            "label": account.name or account.account_id, "provider": "aws",
            "context": account.account_id, "detail": account.environment or "",
            "_haystack": haystack}


def _asset_search_row(kind: str, connection_id, resource_id: str, name: str,
                      resource_type: str, account_id: str | None, region: str | None) -> dict:
    """One catalogued asset as a search hit, bound to the connection that holds it."""
    from cremore.source_config import RESOURCE_SOURCE
    source = RESOURCE_SOURCE.get(resource_type, "notion")
    where = " \u00b7 ".join(v for v in (account_id or "", region or "") if v)
    return {"kind": "asset", "id": f"{kind}:{connection_id}:{resource_id}",
            "label": name or resource_id,
            "provider": "aws" if source == "s3" else source,
            "context": where or str(connection_id), "detail": resource_type,
            "connection_id": str(connection_id), "connection_kind": kind,
            "resource_id": resource_id}


def _matches(rows: list[dict], needle: str, limit: int) -> tuple[list[dict], int]:
    matched = [row for row in rows if not needle or needle in row["_haystack"]]
    matched.sort(key=lambda row: (row["label"].lower(), row["id"]))
    return [{k: v for k, v in row.items() if k != "_haystack"} for row in matched[:limit]], len(matched)


def _finding_search_row(finding, credential) -> dict:
    """One finding as a search hit: what it is, whose it is, and how bad."""
    context = credential.principal_arn or credential.principal_name or credential.service_name or ""
    haystack = " ".join(str(v) for v in (
        credential.credential_type, credential.provider, credential.identifier_hint,
        credential.principal_name, credential.principal_arn, credential.service_name,
        credential.team, credential.business_owner, finding.severity, finding.workflow_status,
    )).lower()
    return {"kind": "finding", "id": str(finding.id), "label": credential.credential_type,
            "provider": (credential.provider or "").lower(), "context": context,
            "detail": f"{finding.severity} \u00b7 {finding.workflow_status}", "_haystack": haystack}


class InMemoryRepository:
    """A dict-backed store honouring the same dedup keys as the SQL schema."""

    audit_key: bytes | None = None

    def __init__(self) -> None:
        self._lock = RLock()
        self.credentials: dict[uuid.UUID, Credential] = {}
        self.exposures: dict[uuid.UUID, Exposure] = {}
        self.findings: dict[uuid.UUID, Finding] = {}
        self.finding_events: dict[uuid.UUID, FindingEvent] = {}
        # Each audit row's entry_mac, chain_seq and chain_mac, the columns SQL keeps beside the row.
        self.audit_marks: dict[uuid.UUID, dict] = {}
        self.siem_events: dict[str, dict] = {}
        self.siem_deliveries: dict[tuple[str, str], dict] = {}
        self.siem_destination_status: dict[str, dict] = {}
        self.installation_settings: dict[str, dict] = {}
        self.jobs: dict[uuid.UUID, ScanJob] = {}
        self.aws_accounts: dict[uuid.UUID, AwsAccount] = {}
        self.reviews: dict[uuid.UUID, GovernanceReview] = {}
        self.rotation_jobs: dict[uuid.UUID, RotationJob] = {}
        self.management_actions: dict[uuid.UUID, ManagementAction] = {}
        self.connections: dict[uuid.UUID, Connection] = {}
        self.rules: dict[uuid.UUID, CustomRule] = {}
        self.ownership_reviews: dict[uuid.UUID, OwnershipReview] = {}  # by finding_id
        self.action_plans: dict[uuid.UUID, ActionPlan] = {}
        self.check_events: dict[uuid.UUID, ConnectionCheckEvent] = {}
        self.tickets: dict[uuid.UUID, WorkflowTicket] = {}
        self.catalogs: dict[tuple[str, uuid.UUID], ScopeCatalog] = {}
        self.scope_profiles: dict[uuid.UUID, ScopeProfile] = {}
        self.drafts: dict[uuid.UUID, SelectionDraft] = {}
        self.plans: dict[uuid.UUID, ScopePlan] = {}
        self.fp_samples: dict[uuid.UUID, FPSample] = {}
        self.fp_profiles: dict[uuid.UUID, FPProfile] = {}
        self._conn_index: dict[tuple[str, str], uuid.UUID] = {}
        self._cred_index: dict[tuple[str, str], uuid.UUID] = {}
        self._exp_index: dict[tuple, uuid.UUID] = {}
        self._finding_index: dict[uuid.UUID, uuid.UUID] = {}
        self.trigger_receipts: dict[str, dict] = {}

    # --- credentials --------------------------------------------------------

    @_synchronized
    def upsert_credential(self, credential: Credential) -> Credential:
        key = (credential.fingerprint, credential.credential_type)
        existing_id = self._cred_index.get(key)
        if existing_id is not None:
            current = self.credentials[existing_id]
            # Update mutable, non-empty fields; never regress a known value.
            for field in ("provider", "identifier", "identifier_hint", "principal_arn",
                          "principal_name", "business_owner", "team", "service_name"):
                value = getattr(credential, field)
                if value:
                    setattr(current, field, value)
            previous_status = current.credential_status
            if credential.credential_status and credential.credential_status != "UNKNOWN":
                current.credential_status = credential.credential_status
            current.updated_at = _now()
            if previous_status != current.credential_status:
                self._record_verification_change(current, previous_status)
            return current
        credential.id = uuid.uuid4()
        credential.created_at = credential.updated_at = _now()
        self.credentials[credential.id] = credential
        self._cred_index[key] = credential.id
        return credential

    def get_credential(self, credential_id: uuid.UUID) -> Credential | None:
        return self.credentials.get(credential_id)

    def get_credential_by_fingerprint(self, fingerprint: str, credential_type: str) -> Credential | None:
        return self.credentials.get(self._cred_index.get((fingerprint, credential_type)))

    def find_component_pairs(self, credential_type: str, fingerprint: str, limit: int) -> list[Exposure]:
        field = {"AWS_ACCESS_KEY_ID": "aws_id_component_fingerprint",
                 "AWS_SECRET_ACCESS_KEY": "aws_secret_component_fingerprint"}[credential_type]
        rows = []
        for row in self.exposures.values():
            cred = self.credentials.get(row.credential_id)
            finding = self.get_finding_for_credential(row.credential_id)
            if (cred and cred.provider == "aws" and cred.credential_type == "AWS_ACCESS_KEY"
                    and finding and finding.workflow_status != "FALSE_POSITIVE" and row.status != "FALSE_POSITIVE"
                    and (row.metadata or {}).get(field) == fingerprint):
                rows.append(row)
        return sorted(rows, key=lambda e: (e.last_seen_at or datetime.min.replace(tzinfo=UTC), str(e.id)), reverse=True)[:limit]

    @_synchronized
    def update_credential(self, credential_id: uuid.UUID, **changes) -> Credential | None:
        previous_status = getattr(self.credentials.get(credential_id), "credential_status", None)
        saved = self._mem_update(self.credentials, credential_id, changes)
        if saved is not None and "credential_status" in changes and previous_status != saved.credential_status:
            self._record_verification_change(saved, previous_status)
        return saved

    def _record_verification_change(self, credential, previous_status):
        finding = self.get_finding_for_credential(credential.id)
        if finding is not None:
            self._queue_siem(finding_updated(finding, credential, change="VERIFICATION",
                                             previous_credential_status=previous_status,
                                             marker=f"{credential.updated_at.isoformat()}:{previous_status}>{credential.credential_status}"))

    @_synchronized
    def installation_id(self) -> str:
        record = self.installation_settings.get(INSTALLATION_KEY)
        if record is None:
            record = {"key": INSTALLATION_KEY, "value": {"id": str(uuid.uuid4())}, "updated_by": "system",
                      "updated_at": _now()}
            self.installation_settings[INSTALLATION_KEY] = record
        return record["value"]["id"]

    @_synchronized
    def _queue_siem(self, event) -> bool:
        event = stamped(event, self.installation_id())
        if event["event_id"] in self.siem_events:
            return False
        self.siem_events[event["event_id"]] = deepcopy(event)
        return True

    # --- exposures ----------------------------------------------------------

    @_synchronized
    def upsert_exposure(self, exposure: Exposure) -> Exposure:
        key = (
            exposure.credential_id, exposure.aws_account_id, exposure.source_connection_id,
            exposure.source_type, exposure.resource_name, exposure.location, exposure.object_version,
        )
        existing_id = self._exp_index.get(key)
        finding = self.get_finding_for_credential(exposure.credential_id)
        if existing_id is not None:
            current = self.exposures[existing_id].model_copy(deep=True)
            removed_at = current.removed_at
            current.last_seen_at = _now()
            current.resource_key = exposure_resource_key(exposure)
            if exposure.severity != "UNKNOWN":
                current.severity = exposure.severity
            current.metadata = observation_metadata(current.metadata, exposure.metadata)
            current.container_key = exposure_container_key(current)
            current.last_scan_id = exposure.last_scan_id or current.last_scan_id
            current.last_source_scan_id = exposure.last_source_scan_id or current.last_source_scan_id
            current.redacted_line = exposure.redacted_line or current.redacted_line
            current.line_number = exposure.line_number if exposure.line_number is not None else current.line_number
            if current.status == "REMOVED":
                current.status = "OPEN"
                current.removed_at = None
                if finding is not None:
                    self._queue_siem(finding_exposure(finding, self.credentials.get(exposure.credential_id),
                        current, reappeared=True, removed_at=removed_at))
            self.exposures[existing_id] = current
            return current
        exposure.id = uuid.uuid4()
        exposure.identity_key = exposure_identity(exposure)
        exposure.resource_key = exposure_resource_key(exposure)
        exposure.container_key = exposure_container_key(exposure)
        exposure.first_seen_at = exposure.last_seen_at = _now()
        if finding is not None:
            self._queue_siem(finding_exposure(finding, self.credentials.get(exposure.credential_id), exposure))
        self.exposures[exposure.id] = exposure
        self._exp_index[key] = exposure.id
        return exposure

    def count_exposures_for_credential(self, credential_id: uuid.UUID) -> int:
        return len({exposure_location(e) for e in self.exposures.values() if e.credential_id == credential_id})

    def best_exposure_for_credential(self, credential_id: uuid.UUID,
                                     preferred_id: uuid.UUID | None = None) -> tuple[str, uuid.UUID | None]:
        candidates = [e for e in self.exposures.values()
                      if e.credential_id == credential_id and e.status != "REMOVED"]
        if not candidates:
            return "UNKNOWN", None
        best = min(candidates, key=lambda e: (-SEVERITY_RANK.get(e.severity, -1),
                                             e.id != preferred_id, str(e.id)))
        return best.severity, best.id

    def exposures_for_credential(self, credential_id: uuid.UUID) -> list[Exposure]:
        return [e for e in self.exposures.values() if e.credential_id == credential_id]

    def findings_with_exposures(self, finding_ids, *, exposure_limit=None):
        """(finding, its credential, the credential's exposures) per existing id, in the given order;
        a repeated id is returned once, as in SqlRepository. exposure_limit bounds the aggregate,
        not each credential; capped callers cannot infer absence from omitted rows."""
        found = [self.findings[i] for i in dict.fromkeys(finding_ids) if i in self.findings]
        owners, grouped = {f.credential_id for f in found}, {}
        count = 0
        for exposure in self.exposures.values():
            if exposure.credential_id not in owners:
                continue
            if exposure_limit is not None and count >= max(0, exposure_limit):
                break
            grouped.setdefault(exposure.credential_id, []).append(exposure)
            count += 1
        return [(f, self.get_credential(f.credential_id), grouped.get(f.credential_id, [])) for f in found]

    def exposures_for_connection(self, connection_id: uuid.UUID) -> list[Exposure]:
        return [e for e in self.exposures.values() if e.source_connection_id == connection_id]

    def exposures_for_resource(self, connection_id: uuid.UUID, source_type: str, resource_name: str,
                               location: str, *, page_id: str | None = None, epoch: str | int | None = None) -> list[Exposure]:
        return [e for e in self.exposures.values() if e.source_connection_id == connection_id
                and e.source_type == source_type and e.resource_name == resource_name and e.location == location
                and (page_id is None or e.metadata.get("page_id") == page_id)
                and (epoch is None or str(e.metadata.get("collector_epoch")) == str(epoch))]

    def exposures_for_root(self, connection_id: uuid.UUID, source_type: str, resource_name: str,
                           *, page_id: str | None = None) -> list[Exposure]:
        root = str(page_id).replace("-", "").lower() if source_type == "notion" and page_id else None
        return [e for e in self.exposures.values() if e.source_connection_id == connection_id
                and e.source_type == source_type and (
                    str(e.metadata.get("page_id", "")).replace("-", "").lower() == root
                    if root else e.resource_name == resource_name)]

    @_synchronized
    def mark_exposure_removed(self, exposure_id: uuid.UUID) -> None:
        exp = self.exposures.get(exposure_id)
        if exp is not None and exp.status != "REMOVED":
            exp.status = "REMOVED"
            exp.removed_at = _now()

    @_synchronized
    def mark_exposure_seen(self, exposure_id: uuid.UUID) -> None:
        exp = self.exposures.get(exposure_id)
        if exp is not None and exp.status != "REMOVED":
            exp.last_seen_at = _now()

    @_synchronized
    def set_exposure_severity(self, exposure_id: uuid.UUID, severity: str, *, metadata: dict | None = None) -> None:
        exp = self.exposures.get(exposure_id)
        if exp is not None:
            exp.severity = severity
            if metadata is not None:
                exp.metadata = observation_metadata(exp.metadata, metadata)
                exp.container_key = exposure_container_key(exp)

    # --- findings -----------------------------------------------------------

    @_synchronized
    def upsert_finding(self, credential_id: uuid.UUID, primary_exposure_id: uuid.UUID, severity: str) -> Finding:
        existing_id = self._finding_index.get(credential_id)
        if existing_id is not None:
            current = self.findings[existing_id]
            current.severity = severity
            current.primary_exposure_id = primary_exposure_id
            current.updated_at = _now()
            return current
        finding = Finding(
            id=uuid.uuid4(),
            credential_id=credential_id,
            primary_exposure_id=primary_exposure_id,
            severity=severity,
        )
        finding.created_at = finding.updated_at = _now()
        exposure = self.exposures.get(primary_exposure_id)
        if exposure is not None and exposure.credential_id != credential_id:
            exposure = None
        event = finding_created(finding, self.credentials.get(credential_id), exposure)
        self.findings[finding.id] = finding
        self._finding_index[credential_id] = finding.id
        self._queue_siem(event)
        return finding

    def get_finding_for_credential(self, credential_id: uuid.UUID) -> Finding | None:
        return self.findings.get(self._finding_index.get(credential_id))

    @_synchronized
    def repair_finding_rollup(self, credential_id: uuid.UUID) -> Finding | None:
        finding = self.get_finding_for_credential(credential_id)
        created = finding is None
        best = self.best_exposure_for_credential(credential_id, finding.primary_exposure_id if finding else None)
        if finding is None:
            if best[1] is None:
                return None
            finding = self.upsert_finding(credential_id, best[1], best[0])
        active = [e for e in self.exposures.values()
                  if e.credential_id == credential_id and e.status != "REMOVED"]
        changes = rollup_changes(finding, best, active=bool(active),
                                unknown=any(e.severity not in SEVERITY_RANK for e in active))
        if not changes:
            return finding
        previous = finding.model_copy(deep=True)
        old_events = self.finding_events.copy()
        try:
            for field, value in changes.items():
                setattr(finding, field, value)
            finding.updated_at = _now()
            self.record_finding_event(FindingEvent(
                finding_id=finding.id, actor="scanner", event_type="ROLLUP_UPDATED",
                from_status=previous.workflow_status, to_status=finding.workflow_status,
                note="LOCATIONS_REMOVED_KEY_RETIREMENT_UNCONFIRMED" if finding.all_locations_removed else "EXPOSURE_ROLLUP_REPAIRED"))
            if (finding.workflow_status, finding.severity) != (previous.workflow_status, previous.severity):
                self._queue_siem(finding_updated(finding, self.credentials.get(credential_id), change="ROLLUP",
                                                 previous_workflow_status=previous.workflow_status,
                                                 previous_severity=previous.severity,
                                                 marker=f"{finding.updated_at.isoformat()}:{previous.workflow_status}>{finding.workflow_status}:"
                                                        f"{previous.severity}>{finding.severity}"))
        except Exception:
            if created:
                self.findings.pop(finding.id, None)
                self._finding_index.pop(credential_id, None)
                event_id = finding_created(previous, None, None)["event_id"]
                self.siem_events.pop(event_id, None)
            else:
                self.findings[finding.id] = previous
            self.finding_events = old_events
            raise
        return finding

    def list_findings(self, *, limit: int | None = None, after: uuid.UUID | None = None) -> list[Finding]:
        return self._page(self.findings, limit, after)

    @staticmethod
    def _page(items, limit, after):
        if limit is None and after is None:
            return list(items.values())
        from heapq import nsmallest

        rows = (f for f in items.values() if after is None or f.id > after)
        return nsmallest(limit if limit is not None else len(items), rows, key=lambda f: f.id)

    def finding_stats(self) -> dict:
        result = {"by_severity": {}, "by_workflow_status": {}, "by_provider": {}}
        for row in self.findings.values():
            cred = self.credentials.get(row.credential_id)
            for group, value in (("by_severity", row.severity), ("by_workflow_status", row.workflow_status),
                                 ("by_provider", (cred.provider if cred else None) or "unknown")):
                result[group][value] = result[group].get(value, 0) + 1
        return result

    def search_connections(self, needle: str, limit: int) -> tuple[list[dict], int]:
        return _matches([_connection_search_row(c) for c in self.connections.values()
                         if not (c.credential_evidence or {}).get("revoked_at")], needle, limit)

    def search_aws_accounts(self, needle: str, limit: int) -> tuple[list[dict], int]:
        return _matches([_aws_account_search_row(a) for a in self.aws_accounts.values()], needle, limit)

    def search_assets(self, needle: str, limit: int) -> tuple[list[dict], int, bool]:
        rows, partial = [], False
        for (kind, cid), catalog in self.catalogs.items():
            if (catalog.completeness or "UNKNOWN") != "COMPLETE":
                partial = True
            for item in catalog.items or []:
                row = _asset_search_row(kind, cid, str(item.get("id", "")),
                                        str(item.get("display_name", "")),
                                        str(item.get("resource_type", "")),
                                        item.get("account_id"), item.get("region"))
                row["_haystack"] = " ".join(str(v) for v in (
                    row["label"], row["resource_id"], row["detail"], row["context"])).lower()
                rows.append(row)
        found, total = _matches(rows, needle, limit)
        return found, total, partial

    def search_findings(self, needle: str, limit: int) -> tuple[list[dict], int]:
        rows = []
        for finding in self.findings.values():
            credential = self.credentials.get(finding.credential_id)
            if credential is None:
                continue
            rows.append(_finding_search_row(finding, credential))
        return _matches(rows, needle, limit)

    def get_finding(self, finding_id: uuid.UUID) -> Finding | None:
        return self.findings.get(finding_id)

    def update_finding_status(self, finding_id: uuid.UUID, workflow_status: str,
                              resolution: str | None = None, *, expected_updated_at=None,
                              expected_status=None, expected_resolution=None) -> Finding | None:
        with self._lock:
            finding = self.findings.get(finding_id)
            if finding is None or (expected_updated_at is not None and finding.updated_at != expected_updated_at):
                return None
            if expected_status is not None and (finding.workflow_status != expected_status or finding.resolution != expected_resolution):
                return None
            previous_status = finding.workflow_status
            finding.workflow_status = workflow_status
            if workflow_status == "ACKNOWLEDGED":
                finding.acknowledged_at = _now()
            elif workflow_status in ("RESOLVED", "FALSE_POSITIVE", "IGNORED"):
                finding.resolved_at = _now()
                finding.resolution = resolution
            elif workflow_status == "OPEN":
                finding.resolved_at = None
                finding.resolution = None
            finding.updated_at = _now()
            if previous_status != workflow_status:
                self._queue_siem(finding_updated(finding, self.credentials.get(finding.credential_id), change="WORKFLOW",
                                                 previous_workflow_status=previous_status,
                                                 marker=f"{finding.updated_at.isoformat()}:{previous_status}>{workflow_status}"))
            return finding

    def assign_finding(self, finding_id: uuid.UUID, assignee: str | None) -> Finding | None:
        finding = self.findings.get(finding_id)
        if finding is None:
            return None
        finding.assigned_to = assignee
        finding.updated_at = _now()
        return finding

    @_synchronized
    def record_finding_event(self, event: FindingEvent, secret: bytes | None = None) -> FindingEvent:
        event.id = uuid.uuid4()
        event.created_at = _now()
        self.finding_events[event.id] = event
        secret = secret or self.audit_key
        self.audit_marks[event.id] = {**_UNSEALED, "entry_mac": audit_chain.entry(secret, event) if secret else None}
        if export_audit(event):
            self._queue_siem(audit_action(event))
        return event

    def _audit_rows(self) -> list[dict]:
        return [{**event.model_dump(), **self.audit_marks.get(event.id, _UNSEALED)} for event in self.finding_events.values()]

    @_synchronized
    def seal_audit(self, secret: bytes, limit: int = 1000, expected: tuple[int, str] | None = None) -> dict:
        """The SQL sealer's rules on the in-memory store (cremore/db/sql.py ``seal_audit``)."""
        done = {"sealed": 0, "head": None, "reset": False, "rewound": False}
        rows = self._audit_rows()
        chained = sorted((row for row in rows if row["chain_seq"] is not None), key=lambda row: row["chain_seq"])
        head = chained[-1] if chained else None
        pending = sorted((row for row in rows if row["chain_seq"] is None), key=lambda row: (row["created_at"], str(row["id"])))
        if head is None:
            if expected is not None:
                if any(row["actor"] == audit_chain.CHAIN_ACTOR and row["event_type"] == audit_chain.REWOUND_EVENT
                       and audit_chain.authentic(secret, row) for row in pending):
                    return {**done, "reset": True}
                self.record_finding_event(audit_chain.chain_event(
                    audit_chain.REWOUND_EVENT, f"expected_seq={expected[0]} head_seq=0"), secret)
                return {**done, "reset": True, "rewound": True}
            if any(row["actor"] == audit_chain.CHAIN_ACTOR and row["event_type"] in audit_chain.CHAIN_EVENTS
                   and audit_chain.authentic(secret, row) for row in rows):
                return {**done, "reset": True}
            started = self.record_finding_event(audit_chain.chain_event(
                audit_chain.GENESIS_EVENT, f"legacy_rows={len(pending)} key={audit_chain.key_id(secret)}"), secret)
            pending.append({**started.model_dump(), **self.audit_marks[started.id]})
            return {**done, "sealed": len(pending), "head": self._seal_rows(secret, pending, 0, "")}
        seq, previous = head["chain_seq"], head["chain_mac"]
        if expected is not None and not audit_chain.same(
                next((row["chain_mac"] for row in chained if row["chain_seq"] == expected[0]), None), expected[1]):
            rewound = self.record_finding_event(audit_chain.chain_event(
                audit_chain.REWOUND_EVENT, f"expected_seq={expected[0]} head_seq={head['chain_seq']}"), secret)
            seq, previous = self._seal_rows(secret, [{**rewound.model_dump(), **self.audit_marks[rewound.id]}], seq, previous)
            done["rewound"] = True
        pending = pending[:limit]
        return {**done, "sealed": len(pending) + done["rewound"], "head": self._seal_rows(secret, pending, seq, previous)}

    def _seal_rows(self, secret: bytes, rows: list[dict], seq: int, previous: str) -> tuple[int, str]:
        for row in rows:
            seq += 1
            previous = audit_chain.link(secret, previous, seq, row)
            self.audit_marks[row["id"]] = {**self.audit_marks.get(row["id"], _UNSEALED), "chain_seq": seq, "chain_mac": previous}
        return seq, previous

    @_synchronized
    def audit_chain_page(self, after_seq: int = 0, limit: int = 2000) -> list[dict]:
        rows = [row for row in self._audit_rows() if row["chain_seq"] is not None and row["chain_seq"] > after_seq]
        return sorted(rows, key=lambda row: row["chain_seq"])[:limit]

    @_synchronized
    def unsealed_audit(self, limit: int = 10000) -> list[dict]:
        rows = [row for row in self._audit_rows() if row["chain_seq"] is None]
        return sorted(rows, key=lambda row: (row["created_at"], str(row["id"])))[:limit]

    @_synchronized
    def audit_rows_outside_chain(self, limit: int = 100) -> list[dict]:
        return [row for row in self._audit_rows() if row["chain_seq"] is not None and row["chain_seq"] < 1][:limit]

    @_synchronized
    def audit_chain_rows(self) -> list[dict]:
        rows = [row for row in self._audit_rows()
                if row["actor"] == audit_chain.CHAIN_ACTOR and row["event_type"] in audit_chain.CHAIN_EVENTS]
        return sorted(rows, key=lambda row: (row["chain_seq"] is None, row["chain_seq"] or 0))

    @_synchronized
    def audit_macs_at(self, seqs: list[int]) -> dict[int, str | None]:
        wanted = set(seqs)
        return {row["chain_seq"]: row["chain_mac"] for row in self._audit_rows() if row["chain_seq"] in wanted}

    def list_finding_events(self, finding_id: uuid.UUID) -> list[FindingEvent]:
        events = [e for e in self.finding_events.values() if e.finding_id == finding_id]
        return sorted(events, key=lambda e: e.created_at or _now())

    def list_events(self, limit: int = 200) -> list[FindingEvent]:
        """The installation-wide audit trail, newest first."""

        # Equal clock ticks retain newest recording first in this ordered store.
        events = sorted(reversed(self.finding_events.values()), key=lambda e: e.created_at or _now(), reverse=True)  # noqa: C414 -- reversing breaks equal-key ties
        return events[:limit]

    # --- installation settings ---------------------------------------------

    @_synchronized
    def get_setting(self, key: str) -> dict | None:
        record = self.installation_settings.get(key)
        return deepcopy(record) if record else None

    @_synchronized
    def list_settings(self, prefix: str) -> list[dict]:
        return [deepcopy(record) for key, record in sorted(self.installation_settings.items())
                if key.startswith(prefix)]

    @_synchronized
    def delete_settings_before(self, prefix: str, cutoff: datetime) -> int:
        """Drop records under a prefix that were last written before the cutoff."""
        old = [key for key, record in self.installation_settings.items()
               if key.startswith(prefix) and record["updated_at"] < cutoff]
        for key in old:
            del self.installation_settings[key]
        return len(old)

    @_synchronized
    def claim_slot(self, key: str, slot: int, updated_by: str) -> bool:
        """Advance a named slot; exactly one caller wins each value."""
        current = self.installation_settings.get(key)
        if current is not None and int(current["value"].get("slot", -1)) >= slot:
            return False
        self.installation_settings[key] = {"key": key, "value": {"slot": slot},
                                           "updated_by": updated_by, "updated_at": _now()}
        return True

    @_synchronized
    def record_siem_event(self, event: dict, audit: FindingEvent | None = None) -> bool:
        """Queue one operational event once; the same event_id is never queued twice. ``audit`` is recorded with
        an event queued now."""
        queued = self._queue_siem(event)
        if queued and audit is not None:
            self.record_finding_event(audit)
        return queued

    def put_setting(self, key: str, value: dict, updated_by: str) -> dict:
        return self.put_settings({key: value}, updated_by)[key]

    @_synchronized
    def put_settings(self, values: dict[str, dict], updated_by: str) -> dict[str, dict]:
        """Publish a validated settings change together, including actor/time."""
        now = _now()
        records = {key: {"key": key, "value": deepcopy(dict(value)),
                         "updated_by": updated_by, "updated_at": now}
                   for key, value in values.items()}
        self.installation_settings.update(records)
        return deepcopy(records)

    @_synchronized
    def put_revisioned_setting(self, key: str, value: dict, updated_by: str) -> dict:
        """Assign a distinct revision while publishing the setting and actor."""
        current = self.installation_settings.get(key)
        revision = int(current["value"].get("revision", 1)) if current is not None else 0
        value = {**value, "revision": revision + 1}
        return self.put_setting(key, value, updated_by)

    # --- jobs ---------------------------------------------------------------

    @_synchronized
    def enqueue_job(self, job: ScanJob) -> ScanJob:
        job.id = uuid.uuid4()
        job.status = JobStatus.QUEUED.value
        job.created_at = _now()
        self.jobs[job.id] = job
        return job

    def active_content_job(self) -> ScanJob | None:
        return next((j for j in sorted(self.jobs.values(), key=lambda j: j.created_at or _now())
                     if j.kind in CONTENT_SCAN_KINDS and j.status in ACTIVE_JOB_STATUSES), None)

    @_synchronized
    def claim_next_job(self, *, execution_role="mixed") -> ScanJob | None:
        from cremore.worker.isolation import accepts

        running = [j for j in self.jobs.values() if j.kind in CONTENT_SCAN_KINDS
                   and j.status in ("RUNNING", "CANCELLING")]
        global_barrier = False
        for job in sorted(self.jobs.values(), key=lambda j: (j.created_at or _now(), str(j.id))):
            if job.status == JobStatus.QUEUED.value and accepts(self, job, execution_role):
                if job.kind in CONTENT_SCAN_KINDS:
                    if global_barrier:
                        continue
                    lane = job_lane(job.kind, job.payload)
                    if any(j.connection_id is None or job.connection_id is None
                           or (j.connection_id == job.connection_id and job_lane(j.kind, j.payload) == lane)
                           for j in running):
                        # A legacy installation-wide run must eventually drain
                        # the active connections instead of starving forever.
                        global_barrier = job.connection_id is None
                        continue
                job.status = JobStatus.RUNNING.value
                job.started_at = _now()
                return job
        return None

    def complete_job(self, job_id: uuid.UUID, objects: int, findings: int, objects_failed: int = 0,
                     coverage: dict | None = None) -> None:
        job = self.jobs.get(job_id)
        if job is not None and job.status not in _STOPPED:
            job.status = JobStatus.SUCCEEDED.value
            job.objects, job.findings, job.objects_failed = objects, findings, objects_failed
            job.coverage = coverage
            job.finished_at = _now()

    def fail_job(self, job_id: uuid.UUID, error: str) -> None:
        job = self.jobs.get(job_id)
        if job is not None and job.status not in _STOPPED:
            job.status = JobStatus.FAILED.value
            job.error = error[:2000]
            job.finished_at = _now()

    def get_job(self, job_id: uuid.UUID) -> ScanJob | None:
        return self.jobs.get(job_id)

    def list_jobs(self, limit: int = 100) -> list[ScanJob]:
        jobs = sorted(self.jobs.values(), key=lambda j: j.created_at or _now(), reverse=True)
        return jobs[:limit]

    @_synchronized
    def job_queue_summary(self) -> dict:
        """How many jobs wait to be claimed and since when the oldest has waited."""
        queued = [job.created_at for job in self.jobs.values() if job.status == JobStatus.QUEUED.value]
        return {"queued": len(queued), "oldest_queued_at": min(queued) if queued else None}

    @_synchronized
    def latest_connection_jobs(self, kinds: tuple[str, ...], status: str) -> dict[uuid.UUID, ScanJob]:
        """Each connection's most recently finished job of these kinds in this status."""
        latest: dict[uuid.UUID, ScanJob] = {}
        for job in self.jobs.values():
            if job.connection_id and job.kind in kinds and job.status == status and job.finished_at:
                current = latest.get(job.connection_id)
                if current is None or job.finished_at > current.finished_at:
                    latest[job.connection_id] = job
        return latest

    def cancel_job(self, job_id: uuid.UUID) -> ScanJob | None:
        """Withdraw a job that is still queued. A running job cannot be cancelled."""

        job = self.jobs.get(job_id)
        if job is None:
            return None
        if job.status == JobStatus.QUEUED.value:
            job.status = JobStatus.CANCELLED.value
            job.finished_at = _now()
        return job

    @_synchronized
    def request_job_cancel(self, job_id: uuid.UUID) -> ScanJob | None:
        """Withdraw a queued job; move a running one to CANCELLING (it keeps the slot)."""

        job = self.jobs.get(job_id)
        if job is None:
            return None
        if job.status == JobStatus.QUEUED.value:
            job.status = JobStatus.CANCELLED.value
            job.finished_at = _now()
        elif job.status == JobStatus.RUNNING.value:
            job.status = JobStatus.CANCELLING.value
        return job

    @_synchronized
    def finish_cancelled_job(self, job_id: uuid.UUID, coverage: dict | None = None) -> None:
        job = self.jobs.get(job_id)
        if job is not None and job.status == JobStatus.CANCELLING.value:
            job.status = JobStatus.CANCELLED.value
            job.coverage = coverage
            job.finished_at = _now()

    # --- enterprise entities (generic dict-backed CRUD) ---------------------

    @staticmethod
    def _mem_create(store: dict, model):
        model.id = uuid.uuid4()
        now = _now()
        if hasattr(model, "created_at"):
            model.created_at = now
        if hasattr(model, "updated_at"):
            model.updated_at = now
        store[model.id] = model
        return model

    @staticmethod
    def _mem_update(store: dict, entity_id, changes: dict):
        m = store.get(entity_id)
        if m is None:
            return None
        for field, value in changes.items():
            setattr(m, field, value)
        if hasattr(m, "updated_at"):
            m.updated_at = _now()
        return m

    def create_aws_account(self, account: AwsAccount) -> AwsAccount:
        return self._mem_create(self.aws_accounts, account)

    def list_aws_accounts(self) -> list[AwsAccount]:
        return list(self.aws_accounts.values())

    def get_aws_account(self, account_id: uuid.UUID, *, for_update: bool = False) -> AwsAccount | None:
        return self.aws_accounts.get(account_id)

    def update_aws_account(self, account_id: uuid.UUID, **changes) -> AwsAccount | None:
        return self._mem_update(self.aws_accounts, account_id, changes)

    def update_aws_account_if_revision(self, account_id: uuid.UUID, revision_field: str, revision: int, **changes) -> AwsAccount | None:
        if revision_field not in ("access_revision", "remediation_access_revision"):
            raise ValueError("unknown revision field")
        with self._lock:
            current = self.aws_accounts.get(account_id)
            if current is None or getattr(current, revision_field) != revision:
                return None
            return self._mem_update(self.aws_accounts, account_id, changes)

    def create_review(self, review: GovernanceReview) -> GovernanceReview:
        return self._mem_create(self.reviews, review)

    def list_reviews(self, *, limit=None, after=None) -> list[GovernanceReview]:
        return self._page(self.reviews, limit, after)

    def get_review(self, review_id: uuid.UUID) -> GovernanceReview | None:
        return self.reviews.get(review_id)

    def update_review(self, review_id: uuid.UUID, **changes) -> GovernanceReview | None:
        return self._mem_update(self.reviews, review_id, changes)

    def create_rotation_job(self, job: RotationJob) -> RotationJob:
        return self._mem_create(self.rotation_jobs, job)

    def list_rotation_jobs(self, *, limit=None, after=None) -> list[RotationJob]:
        return self._page(self.rotation_jobs, limit, after)

    def get_rotation_job(self, job_id: uuid.UUID) -> RotationJob | None:
        return self.rotation_jobs.get(job_id)

    def update_rotation_job(self, job_id: uuid.UUID, **changes) -> RotationJob | None:
        return self._mem_update(self.rotation_jobs, job_id, changes)

    @_synchronized
    def create_management_action(self, action: ManagementAction,
                                 audit: Callable[[ManagementAction], FindingEvent] | None = None) -> ManagementAction:
        created = self._mem_create(self.management_actions, action)
        if audit is not None:
            self.record_finding_event(audit(created))
        return created

    def list_management_actions(self, *, limit=None, after=None) -> list[ManagementAction]:
        return self._page(self.management_actions, limit, after)

    def get_management_action(self, action_id: uuid.UUID) -> ManagementAction | None:
        return self.management_actions.get(action_id)

    @_synchronized
    def update_management_action(self, action_id: uuid.UUID, *, expected_status: str | None = None,
                                 audit: FindingEvent | None = None, **changes) -> ManagementAction | None:
        current = self.management_actions.get(action_id)
        if current is None or (expected_status is not None and current.status != expected_status):
            return None
        saved = self._mem_update(self.management_actions, action_id, changes)
        if audit is not None:
            self.record_finding_event(audit)
        return saved

    # --- connections --------------------------------------------------------

    def create_connection(self, connection: Connection) -> Connection:
        key = (connection.provider, connection.name)
        if key in self._conn_index:
            raise ValueError(f"connection {connection.provider}/{connection.name} already exists")
        connection.id = uuid.uuid4()
        connection.created_at = connection.updated_at = _now()
        self.connections[connection.id] = connection
        self._conn_index[key] = connection.id
        return connection

    def get_connection(self, connection_id: uuid.UUID, *, for_update: bool = False) -> Connection | None:
        return self.connections.get(connection_id)

    def list_connections(self) -> list[Connection]:
        return sorted(self.connections.values(), key=lambda c: c.created_at or _now(), reverse=True)

    @_synchronized
    def update_connection(self, connection_id: uuid.UUID, *, expected_status: str | None = None, **changes) -> Connection | None:
        conn = self.connections.get(connection_id)
        if conn is None or (expected_status is not None and conn.status != expected_status):
            return None
        for field, value in changes.items():
            setattr(conn, field, value)
        conn.updated_at = _now()
        return conn

    # --- operator rules -----------------------------------------------------

    def create_rule(self, rule: CustomRule) -> CustomRule:
        if any(r.name == rule.name for r in self.rules.values()):
            raise ValueError(f"rule {rule.name!r} already exists")
        return self._mem_create(self.rules, rule)

    def list_rules(self) -> list[CustomRule]:
        return sorted(self.rules.values(), key=lambda r: r.created_at or _now())

    def get_rule(self, rule_id: uuid.UUID) -> CustomRule | None:
        return self.rules.get(rule_id)

    def update_rule(self, rule_id: uuid.UUID, **changes) -> CustomRule | None:
        return self._mem_update(self.rules, rule_id, changes)

    def delete_rule(self, rule_id: uuid.UUID) -> bool:
        return self.rules.pop(rule_id, None) is not None

    # --- action plans -------------------------------------------------------

    @_synchronized
    def create_action_plan(self, plan: ActionPlan, audit: FindingEvent | None = None) -> ActionPlan:
        if plan.idempotency_key and any(p.idempotency_key == plan.idempotency_key for p in self.action_plans.values()):
            raise ValueError("duplicate idempotency key")
        now = plan.requested_at or _now()
        if plan.reserves_target(now) and any(p.reserves_target(now) for p in self.list_action_plans(plan.credential_id)):
            raise ValueError("action plan target locked")
        created = self._mem_create(self.action_plans, plan)
        if audit is not None:
            self.record_finding_event(audit.model_copy(update={"target_id": created.id}))
        return created

    def list_action_plans(self, credential_id: uuid.UUID | None = None, limit: int = 500) -> list[ActionPlan]:
        """One credential's plans, or the newest ``limit`` plans of every credential when none is given."""
        plans = [p for p in self.action_plans.values() if credential_id is None or p.credential_id == credential_id]
        plans = sorted(plans, key=lambda p: p.created_at or _now(), reverse=True)
        return plans if credential_id is not None else plans[:limit]

    def get_action_plan(self, plan_id: uuid.UUID) -> ActionPlan | None:
        return self.action_plans.get(plan_id)

    def find_action_plan(self, idempotency_key: str) -> ActionPlan | None:
        return next((p for p in self.action_plans.values() if p.idempotency_key == idempotency_key), None)

    @_synchronized
    def update_action_plan(self, plan_id: uuid.UUID, *, expected_status: str | None = None,
                           audit: FindingEvent | None = None, **changes) -> ActionPlan | None:
        current = self.action_plans.get(plan_id)
        if current is None or (expected_status is not None and current.status != expected_status):
            return None
        saved = self._mem_update(self.action_plans, plan_id, changes)
        if audit is not None:
            self.record_finding_event(audit)
        return saved

    # --- connection check ledger --------------------------------------------

    @_synchronized
    def record_check_event(self, event: ConnectionCheckEvent) -> ConnectionCheckEvent:
        existing = next((e for e in self.check_events.values()
                         if e.job_id == event.job_id and e.stage == event.stage), None)
        if existing is not None:
            if existing.connection_id != event.connection_id:
                raise ValueError("credential check identity mismatch")
            return existing
        event.id = uuid.uuid4()
        # Strictly increasing per connection so the ledger order is deterministic
        # even when two stages are recorded within the clock's resolution.
        latest = max((e.recorded_at for e in self.check_events.values()
                      if e.connection_id == event.connection_id and e.recorded_at), default=None)
        stamp = event.recorded_at or _now()
        if latest is not None and stamp <= latest:
            stamp = latest + timedelta(microseconds=1)
        event.recorded_at = stamp
        self.check_events[event.id] = event
        return event

    @_synchronized
    def finish_credential_check(self, job: ScanJob, connection_changes: dict,
                                event: ConnectionCheckEvent, error: str | None = None) -> ScanJob:
        if set(connection_changes) - {"credential_evidence", "last_error", "last_verified_at", "status"}:
            raise ValueError("unsupported credential check connection update")
        current = self.jobs.get(job.id)
        if (current is None or current.kind != "credential-check" or event.stage != "TERMINAL"
                or event.job_id != current.id or event.connection_id != current.connection_id):
            raise ValueError("credential check identity mismatch")
        if current.status in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return current
        expected = "QUEUED" if event.job_status == "CANCELLED" else "RUNNING"
        if current.status != expected:
            raise ValueError("credential check has incompatible job state")
        if event.job_status not in ("COMPLETED", "FAILED", "CANCELLED"):
            raise ValueError("invalid terminal credential check event")
        if error is not None and event.job_status != "FAILED":
            raise ValueError("credential check error requires FAILED event")
        if any(e.job_id == job.id and e.stage == "TERMINAL" for e in self.check_events.values()):
            raise ValueError("incomplete legacy credential check requires a new job")
        if current.connection_id not in self.connections:
            raise ValueError("credential check connection missing")
        before = deepcopy((current, self.connections[current.connection_id], self.check_events))
        try:
            connection = self.connections[current.connection_id]
            # A late check cannot revive a removed source or certify a replacement credential.
            if (connection_changes and connection.status != "DISABLED"
                    and not (connection.credential_evidence or {}).get("revoked_at")
                    and connection.secret_ref == (current.payload or {}).get("secret_ref")):
                self.update_connection(current.connection_id, **connection_changes)
            self.record_check_event(event)
            if event.job_status == "CANCELLED":
                current.status, current.finished_at = "CANCELLED", _now()
            elif error is not None or event.job_status == "FAILED":
                self.fail_job(current.id, error or "CHECK_FAILED")
            else:
                self.complete_job(current.id, objects=1, findings=0)
        except Exception:
            self.jobs[current.id], self.connections[current.connection_id], self.check_events = before
            raise
        return current

    def list_check_events(self, connection_id: uuid.UUID) -> list[ConnectionCheckEvent]:
        events = [e for e in self.check_events.values() if e.connection_id == connection_id]
        return sorted(events, key=lambda e: (e.recorded_at or _now(), str(e.id)), reverse=True)

    # --- scan scope ------------------------------------------------------------

    def save_catalog(self, catalog: ScopeCatalog) -> ScopeCatalog:
        key = (catalog.kind, catalog.connection_id)
        existing = self.catalogs.get(key)
        if existing is None:
            catalog.id = uuid.uuid4()
            catalog.created_at = catalog.updated_at = _now()
            self.catalogs[key] = catalog
            return catalog
        for field, value in catalog.model_dump(exclude={"id", "created_at", "updated_at"}).items():
            setattr(existing, field, value)
        existing.updated_at = _now()
        return existing

    def get_catalog(self, kind: str, connection_id: uuid.UUID) -> ScopeCatalog | None:
        return self.catalogs.get((kind, connection_id))

    def create_scope_profile(self, profile: ScopeProfile) -> ScopeProfile:
        return self._mem_create(self.scope_profiles, profile)

    def list_scope_profiles(self, kind: str, connection_id: uuid.UUID) -> list[ScopeProfile]:
        items = [p for p in self.scope_profiles.values() if p.kind == kind and p.connection_id == connection_id]
        return sorted(items, key=lambda p: p.created_at or _now())

    def get_scope_profile(self, profile_id: uuid.UUID) -> ScopeProfile | None:
        return self.scope_profiles.get(profile_id)

    @_synchronized
    def update_scope_profile(self, profile_id: uuid.UUID, *, expected_version: int | None = None, **changes) -> ScopeProfile | None:
        current = self.scope_profiles.get(profile_id)
        if current is None or (expected_version is not None and current.version != expected_version):
            return None
        return self._mem_update(self.scope_profiles, profile_id, changes)

    def create_draft(self, draft: SelectionDraft) -> SelectionDraft:
        return self._mem_create(self.drafts, draft)

    def get_draft(self, draft_id: uuid.UUID) -> SelectionDraft | None:
        return self.drafts.get(draft_id)

    def update_draft(self, draft_id: uuid.UUID, **changes) -> SelectionDraft | None:
        return self._mem_update(self.drafts, draft_id, changes)

    def create_plan(self, plan: ScopePlan) -> ScopePlan:
        return self._mem_create(self.plans, plan)

    def get_plan(self, plan_id: uuid.UUID) -> ScopePlan | None:
        return self.plans.get(plan_id)

    def update_plan(self, plan_id: uuid.UUID, **changes) -> ScopePlan | None:
        return self._mem_update(self.plans, plan_id, changes)

    def list_scheduled_profiles(self, full_scan_default: int = 0) -> list[ScopeProfile]:
        """Profiles a schedule runs: a cadence of their own, or none for full scans while the installation has one."""
        return [p for p in self.scope_profiles.values() if p.schedule_minutes > 0 or (p.full_scan_minutes or 0) > 0
                or (p.full_scan_minutes is None and full_scan_default > 0)]

    def list_scope_profiles_page(self, cursor: str | None = None, limit: int = 100) -> tuple[list[ScopeProfile], str | None]:
        limit = max(1, min(int(limit), 1000))
        after = uuid.UUID(cursor) if cursor else None
        values = sorted((p for p in self.scope_profiles.values() if after is None or p.id.int > after.int), key=lambda p: p.id.int)
        batch = values[:limit]
        return batch, str(batch[-1].id) if len(values) > limit else None

    @_synchronized
    def slot_receipt_state(self, key: str, begins: datetime) -> tuple[bool, uuid.UUID | None]:
        receipt = self.trigger_receipts.get(key)
        if receipt is None:
            return False, None
        job = self.jobs.get(receipt["job_id"])
        if job is not None and receipt_reopens(key, begins, job.status, job.payload.get("slot_receipt"),
                                               job.payload.get("requested_by"), job.created_at):
            return False, job.id
        return True, None

    @_synchronized
    def slot_run_ended(self, key: str, begins: datetime) -> bool:
        receipt = self.trigger_receipts.get(key)
        job = self.jobs.get(receipt["job_id"]) if receipt else None
        return self.slot_receipt_state(key, begins)[0] and (job is None or job.status not in ACTIVE_JOB_STATUSES)

    def prune_trigger_receipts(self, before: datetime, limit: int = 10000) -> int:
        if before.tzinfo is None:
            raise ValueError("receipt retention requires a timezone")
        removable = []
        for key, receipt in sorted(self.trigger_receipts.items(), key=lambda item: item[1]["created_at"]):
            job = self.jobs.get(receipt["job_id"])
            if (receipt["created_at"] < before and job and job.status in {"SUCCEEDED", "FAILED", "CANCELLED"}
                    and job.payload.get("mode") != "POLICY_SWEEP" and job.payload.get("trigger") != "POLICY_SWEEP"):
                removable.append(key)
                if len(removable) >= max(1, min(int(limit), 10000)):
                    break
        for key in removable:
            del self.trigger_receipts[key]
        return len(removable)

    @_synchronized
    def consume_scope_plan(self, plan_id: uuid.UUID, expected_version: int, job: ScanJob) -> tuple[ScanJob, bool]:
        plan = self.plans.get(plan_id)
        if plan is None or plan.profile_version != expected_version:
            raise ValueError("SCOPE_PLAN_STALE")
        if job.kind != "scope" or job.connection_id != plan.connection_id:
            raise ValueError("SCOPE_PLAN_JOB_MISMATCH")
        if plan.job_id is not None:
            existing = self.jobs.get(plan.job_id)
            if existing is None:
                raise ValueError("SCOPE_PLAN_JOB_MISSING")
            return existing, False
        if not plan.executable or (plan.expires_at and plan.expires_at <= _now()):
            raise ValueError("SCOPE_PLAN_STALE")
        queued = self.enqueue_job(job.model_copy(update={"payload": {**job.payload, "plan_id": str(plan.id)}}))
        plan.job_id = queued.id
        return queued, True

    @_synchronized
    def enqueue_triggered_scope(self, plan: ScopePlan, job: ScanJob, receipt_key: str,
                                replaces: uuid.UUID | None = None) -> tuple[ScanJob, bool]:
        if len(receipt_key) != 64 or any(c not in "0123456789abcdef" for c in receipt_key):
            raise ValueError("INVALID_TRIGGER_RECEIPT")
        if job.kind != "scope" or job.connection_id != plan.connection_id:
            raise ValueError("SCOPE_PLAN_JOB_MISMATCH")
        receipt = self.trigger_receipts.get(receipt_key)
        # A receipt that still names ``replaces`` is swapped below; any other one answers this request.
        if receipt and (replaces is None or receipt["job_id"] != replaces):
            return self.jobs[receipt["job_id"]], False
        plan = plan.model_copy(deep=True)
        plan.id = plan.id or uuid.uuid4()
        if plan.id in self.plans:
            raise ValueError("TRIGGER_PLAN_ALREADY_EXISTS")
        queued = self.enqueue_job(job.model_copy(update={"payload": {**job.payload, "plan_id": str(plan.id)}}))
        plan.job_id, plan.created_at = queued.id, _now()
        self.plans[plan.id] = plan
        self.trigger_receipts[receipt_key] = {"job_id": queued.id, "plan_id": plan.id, "created_at": _now()}
        return queued, True

    @_synchronized
    def coalesce_scheduled_scope(self, receipt_key: str, profile: ScopeProfile, auth_revision: str,
                                 modes: tuple[str, ...], since: datetime,
                                 replaces: uuid.UUID | None = None) -> ScanJob | None:
        """Answer a schedule slot with a whole-scope run of this approval (``profile``'s version, ``auth_revision``) in
        one of ``modes``: a scheduled run or an Admin's, never an event's, a rescan's or a continuation's, that is still
        QUEUED or began at or after ``since``, the slot's start, and did not fail. The slot's receipt names it,
        replacing one that still names ``replaces`` (a reopened slot's ended run)."""
        if len(receipt_key) != 64 or any(c not in "0123456789abcdef" for c in receipt_key):
            raise ValueError("INVALID_TRIGGER_RECEIPT")
        answer = next((job for job in sorted(self.jobs.values(), key=lambda job: job.created_at or _now())
                       if job.kind == "scope" and job.connection_id == profile.connection_id
                       and (job.status == "QUEUED" or job.status in ("RUNNING", "SUCCEEDED")
                            and job.started_at is not None and job.started_at >= since)
                       and job.payload.get("profile_id") == str(profile.id)
                       and job.payload.get("profile_version") == profile.version
                       and job.payload.get("auth_revision") == auth_revision
                       and job.payload.get("trigger") in ("BASELINE", "SCHEDULE")
                       and job.payload.get("mode", "BASELINE") in modes), None)
        if answer is not None:
            receipt = {"job_id": answer.id, "plan_id": uuid.UUID(answer.payload["plan_id"]), "created_at": _now()}
            if replaces is not None and self.trigger_receipts.get(receipt_key, {}).get("job_id") == replaces:
                del self.trigger_receipts[receipt_key]
            self.trigger_receipts.setdefault(receipt_key, receipt)
        return answer

    @_synchronized
    def active_scope_runs(self, connection_id: uuid.UUID, profile_id: str, profile_version: int) -> list[ScanJob]:
        """This profile version's queued or running whole-scope runs (BASELINE or SCHEDULE; no trigger is BASELINE) on
        one connection, newest first."""
        return sorted((job for job in self.jobs.values()
                       if job.kind == "scope" and job.status in ("QUEUED", "RUNNING")
                       and job.connection_id == connection_id
                       and job.payload.get("profile_id") == profile_id
                       and job.payload.get("profile_version") == profile_version
                       and job.payload.get("trigger", "BASELINE") in ("BASELINE", "SCHEDULE")),
                      key=lambda job: job.created_at or _now(), reverse=True)

    # --- learned false-positive profiles ---------------------------------------

    @staticmethod
    def _fp_key(item) -> tuple:
        return (item.scope_kind, item.scope_id, item.source_type, item.detector_name, item.credential_type)

    def create_fp_sample(self, sample: FPSample) -> FPSample:
        return self._mem_create(self.fp_samples, sample)

    def list_fp_samples(self, **key) -> list[FPSample]:
        wanted = (key["scope_kind"], key["scope_id"], key["source_type"], key["detector_name"], key["credential_type"])
        return sorted((s for s in self.fp_samples.values() if self._fp_key(s) == wanted), key=lambda s: s.created_at or _now())

    def delete_fp_samples(self, **key) -> int:
        doomed = [s.id for s in self.list_fp_samples(**key)]
        for sid in doomed:
            del self.fp_samples[sid]
        return len(doomed)

    def get_fp_profile(self, **key) -> FPProfile | None:
        wanted = (key["scope_kind"], key["scope_id"], key["source_type"], key["detector_name"], key["credential_type"])
        return next((p for p in self.fp_profiles.values() if self._fp_key(p) == wanted), None)

    def get_fp_profile_by_id(self, profile_id: uuid.UUID) -> FPProfile | None:
        return self.fp_profiles.get(profile_id)

    def save_fp_profile(self, profile: FPProfile) -> FPProfile:
        existing = self.get_fp_profile(**{k: getattr(profile, k) for k in
                                          ("scope_kind", "scope_id", "source_type", "detector_name", "credential_type")})
        if existing is None:
            return self._mem_create(self.fp_profiles, profile)
        return self._mem_update(self.fp_profiles, existing.id,
                                profile.model_dump(exclude={"id", "created_at", "updated_at"}))

    def list_fp_profiles(self) -> list[FPProfile]:
        return sorted(self.fp_profiles.values(), key=lambda p: p.updated_at or _now(), reverse=True)

    # --- internal workflow tickets -------------------------------------------

    def create_ticket(self, ticket: WorkflowTicket) -> WorkflowTicket:
        return self._mem_create(self.tickets, ticket)

    def list_tickets(self, credential_id: uuid.UUID | None = None, *, limit=None, offset=0) -> list[WorkflowTicket]:
        items = [t for t in self.tickets.values() if credential_id is None or t.credential_id == credential_id]
        return sorted(items, key=lambda t: (t.created_at or _now(), t.id), reverse=True)[offset:None if limit is None else offset + limit]

    def get_ticket(self, ticket_id: uuid.UUID) -> WorkflowTicket | None:
        return self.tickets.get(ticket_id)

    @_synchronized
    def update_ticket(self, ticket_id: uuid.UUID, *, expected_version: int | None = None, **changes) -> WorkflowTicket | None:
        current = self.tickets.get(ticket_id)
        if current is None or (expected_version is not None and current.version != expected_version):
            return None
        return self._mem_update(self.tickets, ticket_id, changes)

    # --- ownership reviews (one per finding) --------------------------------

    def get_ownership_review(self, finding_id: uuid.UUID) -> OwnershipReview | None:
        return self.ownership_reviews.get(finding_id)

    @_synchronized
    def save_ownership_review(self, review: OwnershipReview) -> OwnershipReview:
        current = self.ownership_reviews.get(review.finding_id)
        now = _now()
        if current is None:
            review.id = uuid.uuid4()
            review.created_at = review.updated_at = now
            self.ownership_reviews[review.finding_id] = review
            return review
        for field in ("status", "assigned_team", "due_at", "closed_reason", "revision", "updated_by"):
            setattr(current, field, getattr(review, field))
        current.updated_at = now
        return current

    @_synchronized
    def save_ownership_reviews(self, reviews: list[OwnershipReview], *, audit_actor: str | None) -> list[OwnershipReview] | None:
        """Advance every requested revision exactly once, or change nothing; ``audit_actor`` audits each change."""
        if len({review.finding_id for review in reviews}) != len(reviews):
            raise ValueError("duplicate ownership review")
        if any(review.finding_id not in self.findings or review.revision != (
                self.ownership_reviews[review.finding_id].revision + 1
                if review.finding_id in self.ownership_reviews else 1) for review in reviews):
            return None
        now = _now()
        prepared = {}
        for review in reviews:
            current = self.ownership_reviews.get(review.finding_id)
            prepared[review.finding_id] = review.model_copy(update={
                "id": current.id if current else uuid.uuid4(),
                "created_at": current.created_at if current else now, "updated_at": now,
            }, deep=True)
        previous = {finding_id: self.ownership_reviews[finding_id].status for finding_id in prepared if finding_id in self.ownership_reviews}
        self.ownership_reviews.update(prepared)
        if audit_actor is not None:
            for review in prepared.values():
                self.record_finding_event(review.audit_event(previous.get(review.finding_id), audit_actor))
        return list(prepared.values())
