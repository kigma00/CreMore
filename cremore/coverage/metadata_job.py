"""Page-wise metadata I/O outside locks, atomic publish under the task lease."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from cremore.coverage import metadata_auth as _auth
from cremore.coverage import metadata_stream as _stream
from cremore.coverage.collector_runtime import CollectionContext
from cremore.coverage.metadata_auth import resolved_slots
from cremore.coverage.metadata_models import (
    MetadataConnectionSpec,
    MetadataFinish,
    MetadataPage,
    checkpoint_json,
    metadata_contract,
    same_contract,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.providers import collector_for
from cremore.coverage.store import RUN_LIFETIME, CoverageError, utc
from cremore.db.task_store import LeaseLost, TaskStore

# An operator's pause holds a running collection after its current request:
# the task is deferred with its checkpoint and its run stays open, so resuming
# continues the same run. It names the job it was given for; a stale one is inert.
PAUSED = "METADATA_COLLECTION_PAUSED"
PAUSE_RECHECK_SECONDS = 30
# A paused run is closed with what it committed before the store's run lifetime
# would refuse it; resuming later starts a new run. A collection paused before it
# opened a run ends after as long, so it does not hold the connection's job slot.
PAUSE_EXPIRED = "METADATA_COLLECTION_PAUSE_EXPIRED"
PAUSE_EXPIRY_MARGIN = timedelta(minutes=10)


def pause_key(connection_id):
    return f"metadata_collection_pause:{connection_id}"


def pause_since(repo, connection_id, job_id):
    """When the pause naming this job was requested, or None when the job is not paused."""
    record = repo.get_setting(pause_key(connection_id))
    if not record or (record.get("value") or {}).get("job_id") != str(job_id):
        return None
    return record.get("updated_at") or datetime.now(UTC)


def paused(repo, connection_id, job_id):
    return pause_since(repo, connection_id, job_id) is not None


# Compatibility for callers that used these helpers before library extraction.
resolve_slots = _auth.resolve_slots
batches_for = _stream.batches_for
source_summary = _stream.source_summary
_safe_code = _stream.safe_error_code


def run(worker, job, task, context):
    cid = uuid.UUID(job.payload["coverage_connection_id"])
    revision = job.payload["coverage_revision"]
    store = MetadataStore(worker.repo)
    owner = store.require_connection(cid)
    spec = MetadataConnectionSpec.model_validate(owner["spec"])
    collector = collector_for(spec.provider)
    collector.validate_spec(spec)
    state = dict(task.get("checkpoint") or {})
    rid = uuid.UUID(state["metadata_run_id"]) if state.get("metadata_run_id") else None
    snapshot = store.run_detail(rid, limit=1)["run"] if rid else None
    if snapshot and snapshot["status"] != "RUNNING":
        raise CoverageError("METADATA_RUN_ALREADY_CLOSED")
    batch_index, item_count = int(state.get("next_batch", 0)), int(state.get("item_count", 0))
    terminal = None
    paused_at = None

    def check():
        # This context checks cancellation, heartbeat ownership, revision and an
        # operator's pause in one transaction. It is closed before an adapter is
        # allowed to perform its next I/O.
        nonlocal paused_at
        with context() as repo:
            current = MetadataStore(repo).require_connection(cid)
            if not current["enabled"] or current["revision"] != revision:
                raise CoverageError("CONNECTION_REVISION_CONFLICT")
            if spec.provider == "gcp":
                from cremore.coverage.gcp_store import linked_source_disabled
                if linked_source_disabled(repo, cid):
                    raise CoverageError("GCP_SOURCE_DISABLED")
            paused_at = pause_since(repo, cid, job.id)
        if paused_at is not None:
            raise CoverageError(PAUSED)

    def hold():
        """Defer a paused task; end it first if the pause would outlive its run, or has lasted as long without one."""
        now = datetime.now(UTC)
        if rid is None or snapshot is None:
            if paused_at is not None and now >= utc(paused_at) + RUN_LIFETIME - PAUSE_EXPIRY_MARGIN:
                # Nothing was committed: the job fails with the reason, freeing the connection.
                TaskStore(worker.repo).fail(task["id"], task["token"], PAUSE_EXPIRED)
                return
        elif now >= utc(snapshot["started_at"]) + RUN_LIFETIME - PAUSE_EXPIRY_MARGIN:
            with context() as repo:
                bound = MetadataStore(repo)
                closed = bound.finish(cid, rid, MetadataFinish(batch_count=batch_index, item_count=item_count,
                                                               status="PARTIAL", reasons=[PAUSE_EXPIRED]))
                TaskStore(repo).finish(task["id"], task["token"], {
                    "metadata_items": item_count, "coverage_status": closed["status"],
                    "coverage_run_id": str(rid), **source_summary(bound, rid)})
            return
        TaskStore(worker.repo).defer(task["id"], task["token"], PAUSED, delay_seconds=PAUSE_RECHECK_SECONDS)

    try:
        check()
    except CoverageError as exc:
        if str(exc) != PAUSED:
            raise
        hold()
        return

    def read_records():
        return store.iter_records(rid) if rid else iter(())

    # Resolve once per attempt. Planning and generator creation share the same
    # cleanup boundary as iteration, including unsupported retries.
    from cremore.onboarding.credential_access import resolver_for_child

    resolver = resolver_for_child(worker.repo, "metadata", cid, getattr(worker, "metadata_secret_resolver", None),
            spec=spec, settings=getattr(worker, "settings", None))
    with resolved_slots(spec, resolver,
                        collector.optional_secret_roles) as secrets:
        value_context = None
        if collector.uses_value_context and (spec.options.include_values or spec.options.include_provider_hashes):
            key = worker.orchestrator.config.fingerprint_key
            value_context = {"engine": worker.orchestrator.engine,
                             "key_id": hashlib.sha256(key).hexdigest() if key else None,
                             "engine_digest": worker.orchestrator.engine.detection_digest,
                             "policy_digest": worker.orchestrator.coverage_policy_digest}
            if spec.provider == "azure_resource_manager" and spec.options.azure_storage_accounts:
                from cremore.coverage.metadata_correlation import sas_candidates
                value_context["sas_candidate_status"] = {}
                value_context["sas_candidates"] = sas_candidates(
                    worker.repo, spec.options.azure_storage_accounts, status=value_context["sas_candidate_status"])
        recollection_plan = None
        if job.payload.get("retry_from_run"):
            if not collector.supports_recollection:
                raise CoverageError("METADATA_RECOLLECTION_UNSUPPORTED")
            previous = store.run_detail(uuid.UUID(job.payload["retry_from_run"]), limit=1)["run"]
            if previous["connection_id"] != cid or previous["revision"] != revision or previous["status"] == "RUNNING":
                raise CoverageError("INCOMPATIBLE_RECOLLECTION_RUN")
            recollection_plan = collector.plan_recollection(store.iter_records(previous["id"]),
                scope_id=job.payload.get("retry_scope_id"), operations=job.payload.get("retry_operations") or None,
                include_unverified=job.payload.get("include_unverified", False))
        identity_digest = None
        if collector.uses_identity_digest:
            from cremore.identity.keys import Digester

            try:
                identity_digest = Digester(worker.orchestrator.config.fingerprint_key)
            except ValueError:
                raise CoverageError("IDENTITY_KEY_UNAVAILABLE") from None
        export_control = None
        if collector.uses_export_control:
            from cremore.coverage.github_exports import ExportControl, applicable
            if applicable(spec) and recollection_plan is None:
                export_control = ExportControl(worker.repo, spec, job.id, context=context)
        collection = CollectionContext(secrets=secrets, checkpoint=state.get("provider", {}),
            check=check, read_records=read_records, value_context=value_context,
            recollection_plan=recollection_plan, identity_digest=identity_digest, export_control=export_control)
        try:
            for returned in collector.collect(spec, collection):
                if terminal is not None:
                    raise CoverageError("METADATA_PAGE_AFTER_TERMINAL")
                page = MetadataPage.model_validate(returned)
                encoded = page.model_dump_json()
                if any(value in encoded for slot, value in secrets.items()
                       if slot not in ("username", "app_id", "installation_id", "client_id", "tenant_id") and len(value) >= 8):
                    raise CoverageError("PROVIDER_AUTH_VALUE_IN_METADATA")
                check()
                if snapshot is None and page.status == "WAITING" and not page.principal_verified and page.principal_id is None and not page.records:
                    # A rate-limited caller-self request has not established the
                    # immutable principal contract yet. Persist only its backoff.
                    with context() as repo:
                        TaskStore(repo).checkpoint(task["id"], task["token"], checkpoint_json({
                            "next_batch": batch_index, "item_count": item_count, "provider": page.checkpoint}))
                    TaskStore(worker.repo).defer(task["id"], task["token"],
                        page.reasons[0] if page.reasons else "METADATA_RETRY_LATER", delay_seconds=page.retry_after_seconds)
                    return
                contract = metadata_contract(spec, principal_id=page.principal_id, principal_verified=page.principal_verified).model_dump()
                if snapshot is not None and not same_contract(snapshot["contract"], contract):
                    raise CoverageError("COLLECTOR_PRINCIPAL_MISMATCH")
                batches = list(batches_for(page.records, batch_index))
                with context() as repo:
                    bound = MetadataStore(repo)
                    current = bound.require_connection(cid)
                    if current["revision"] != revision or not current["enabled"]:
                        raise CoverageError("CONNECTION_REVISION_CONFLICT")
                    if spec.provider == "gcp":
                        from cremore.coverage.gcp_store import linked_source_disabled
                        if linked_source_disabled(repo, cid):
                            raise CoverageError("GCP_SOURCE_DISABLED")
                    if snapshot is None:
                        snapshot = bound.start(cid, revision, str(job.id), contract)
                        rid = snapshot["id"]
                    for batch in batches:
                        bound.append(cid, rid, batch, trusted_discovery=True)
                        item_count += len(batch.items)
                        batch_index += 1
                    next_state = checkpoint_json({"metadata_run_id": str(rid), "next_batch": batch_index,
                                                  "item_count": item_count, "provider": page.checkpoint})
                    TaskStore(repo).checkpoint(task["id"], task["token"], next_state)
                    if page.status not in (None, "WAITING"):
                        gcp_summary = {}
                        if spec.provider == "gcp" and page.status in ("COMPLETE", "PARTIAL"):
                            from cremore.coverage.gcp_store import GcpStore
                            gcp_summary = GcpStore(repo).reconcile(cid, rid, list(bound.iter_records(rid)))
                        terminal = bound.finish(cid, rid, MetadataFinish(batch_count=batch_index, item_count=item_count,
                                                                         status=page.status, reasons=page.reasons))
                        TaskStore(repo).finish(task["id"], task["token"], {"metadata_items": item_count,
                            "coverage_status": terminal["status"], "coverage_run_id": str(rid),
                            **gcp_summary, **source_summary(bound, rid)})
                if page.status == "WAITING":
                    TaskStore(worker.repo).defer(task["id"], task["token"],
                        page.reasons[0] if page.reasons else "METADATA_RETRY_LATER", delay_seconds=page.retry_after_seconds)
                    return
                if terminal is not None:
                    # Never execute an adapter past its final page: next() can do I/O.
                    break
            if terminal is None:
                raise CoverageError("METADATA_TERMINAL_REPORT_REQUIRED")
        except Exception as exc:
            code = _safe_code(exc)
            if code == PAUSED:
                # The run and the last committed checkpoint wait for the resume (within the run lifetime).
                hold()
                return
            if code in {"RETRY_LATER", "RATE_LIMIT_CIRCUIT_OPEN", "RATE_LIMITED", "METADATA_RETRY_LATER", "METADATA_TEMPORARY_FAILURE"}:
                TaskStore(worker.repo).defer(task["id"], task["token"], code, delay_seconds=60)
                return
            if rid is not None:
                try:
                    with context() as repo:
                        MetadataStore(repo).abort(cid, rid, code)
                except LeaseLost:
                    pass
            raise
