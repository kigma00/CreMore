"""Persisted metadata schedules. The connection row serializes worker replicas."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.providers import validate_spec
from cremore.coverage.store import utc
from cremore.db.task_store import TaskStore
from cremore.domain.models import FindingEvent, ScanJob


def connection_job(repo, cid, *, active=False):
    """Find this connection's job without truncating the installation's queue."""
    def matches(job):
        return (job.kind == METADATA_JOB_KIND
                and job.payload.get("coverage_connection_id") == str(cid)
                and (not active or job.status in ("QUEUED", "RUNNING", "CANCELLING")))

    if getattr(repo, "engine", None) is None:
        with repo._lock:
            return next(iter(sorted((job for job in repo.jobs.values() if matches(job)),
                                    key=lambda job: job.created_at, reverse=True)), None)
    from cremore.db.schema import scan_jobs
    query = select(scan_jobs.c.id).where(
        scan_jobs.c.kind == METADATA_JOB_KIND,
        scan_jobs.c.payload["coverage_connection_id"].as_string() == str(cid))
    if active:
        query = query.where(scan_jobs.c.status.in_(("QUEUED", "RUNNING", "CANCELLING")))
    with repo.engine.connect() as conn:
        jid = conn.execute(query.order_by(scan_jobs.c.created_at.desc()).limit(1)).scalar()
    return repo.get_job(jid) if jid else None


def next_collection_at(repo, receipt_key, latest, minutes, *, revision=None, now=None):
    """Shared eligibility clock; revision=None preserves the legacy AWS receipt contract."""
    receipt = (repo.get_setting(receipt_key) or {}).get("value", {})
    times = [utc(latest.created_at)] if latest else []
    if receipt.get("queued_at") and (revision is None or receipt.get("revision") == revision):
        times.append(utc(datetime.fromisoformat(receipt["queued_at"])))
    return max(times) + timedelta(minutes=minutes) if times else utc(now or datetime.now(UTC))


def poll_metadata_schedules(repo, settings, *, now=None):
    result = {"enqueued": 0, "skipped": 0}
    # Metadata has its own explicit interval. The content-scan switch does not
    # start or stop it; the installation's schedule hard lock still applies.
    if not settings.scan_schedules_allowed:
        return result
    now = utc(now or datetime.now(UTC))
    store = MetadataStore(repo)
    for candidate in store.list_connections():
        if (not candidate["enabled"] or candidate["spec"].get("schema_version") != 2
                or not candidate["spec"].get("schedule_minutes")):
            continue
        with store.transaction() as conn:
            bound = TaskStore(repo)._bound(conn)
            current = MetadataStore(bound)
            row = current._get(conn, "connections", candidate["id"], lock=True)
            if not row or not row["enabled"]:
                continue
            spec = MetadataConnectionSpec.model_validate(row["spec"])
            if not spec.schedule_minutes:
                continue
            if spec.provider == "gcp":
                from cremore.coverage.gcp_store import linked_source_disabled
                if linked_source_disabled(bound, row["id"]):
                    continue
                if spec.auth_type == "google_oauth":
                    from cremore_gcp_provider.oauth import REAUTH
                    latest_run = current.connection_runs(row["id"], limit=1)["items"]
                    if (latest_run and latest_run[0]["revision"] == row["revision"]
                            and REAUTH.intersection(latest_run[0]["reasons"])):
                        result["skipped"] += 1
                        continue
            validate_spec(spec)
            if connection_job(bound, row["id"], active=True):
                result["skipped"] += 1
                continue
            from cremore.coverage.github_exports import next_create_at
            export_due = next_create_at(bound, spec)
            if export_due is not None and now < export_due:
                result["skipped"] += 1
                continue
            receipt_key = "metadata-schedule:" + str(row["id"])
            latest = connection_job(bound, row["id"])
            if now < next_collection_at(bound, receipt_key, latest, spec.schedule_minutes, revision=row["revision"], now=now):
                result["skipped"] += 1
                continue
            job = bound.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
                "provider": spec.provider, "coverage_connection_id": str(row["id"]),
                "coverage_revision": row["revision"]}))
            bound.put_setting(receipt_key, {"queued_at": now.isoformat(),
                "revision": row["revision"], "job_id": str(job.id)}, "metadata-schedule")
            bound.record_finding_event(FindingEvent(target_type="coverage_connection",
                target_id=row["id"], actor="metadata-schedule",
                event_type="METADATA_COLLECTION_SCHEDULED", note=str(job.id)))
            result["enqueued"] += 1
    return result
