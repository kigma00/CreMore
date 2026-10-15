"""AWS schema-one inventory onboarding and scheduling under account approvals."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from cremore_aws_provider import aws_access, aws_inventory_settings
from sqlalchemy import select

from cremore.coverage import JOB_KIND
from cremore.coverage.models import ConnectionSpec, worker_collected
from cremore.coverage.scheduling import next_collection_at
from cremore.coverage.store import CoverageError, CoverageStore, utc
from cremore.db.task_store import TaskStore
from cremore.domain.models import ScanJob


def _connections(repo, account_id, provider):
    return [row for row in CoverageStore(repo).list_connections()
            if row["spec"].get("schema_version", 1) == 1
            and row["spec"].get("provider") == provider and row["spec"].get("account_id") == account_id]


def _ensure(repo, account, actor, provider, **options):
    store = CoverageStore(repo)
    cid = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:" + ("iam-inventory/" if provider == "aws_iam"
                                                   else "cloudtrail-inventory/") + account.account_id)
    rows = _connections(repo, account.account_id, provider)
    if rows:
        # A disabled connection is an explicit choice. Never silently replace it.
        row = next((row for row in rows if row["id"] == cid), rows[0])
        if provider == "aws_cloudtrail" and row["id"] == cid and row["enabled"] and row["spec"].get("schedule_source") != "connection":
            changes = {key: options[key] for key in ("regions", "window_days", "cloudtrail_source",
                                                    "trail_bucket", "trail_prefixes")}
            if any(row["spec"].get(key) != value for key, value in changes.items()):
                # The reserved automatic connection follows explicitly approved
                # administrator settings. A custom connection keeps its own scope.
                spec = ConnectionSpec.model_validate({**row["spec"], **changes})
                row = store.change(cid, row["revision"], actor, spec=spec)[0]
        return row
    spec = ConnectionSpec(name=("IAM " if provider == "aws_iam" else "CloudTrail ") + account.account_id,
                          provider=provider, account_id=account.account_id, **options)
    try:
        return store.create(spec, actor, connection_id=cid)[0]
    except CoverageError as exc:
        if str(exc) != "CONNECTION_EXISTS":
            raise
        row = store.get(cid)
        if not row or row["spec"].get("provider") != provider or row["spec"].get("account_id") != account.account_id:
            raise CoverageError("AWS_INVENTORY_CONNECTION_CONFLICT") from None
        return row


def ensure_iam_connection(repo, account, actor, *, schedule_minutes=0):
    return _ensure(repo, account, actor, "aws_iam", service_credentials=True,
                   credential_report=True, last_used=True, schedule_minutes=schedule_minutes)


def ensure_aws_inventory_connections(repo, settings, account, actor, *, schedule_minutes=0):
    rows = [ensure_iam_connection(repo, account, actor, schedule_minutes=schedule_minutes)]
    config = aws_inventory_settings.config(settings, repo)
    if config["cloudtrail_enabled"]:
        rows.append(_ensure(repo, account, actor, "aws_cloudtrail", regions=config["regions"],
                            window_days=config["window_days"], schedule_minutes=schedule_minutes,
                            cloudtrail_source=config["cloudtrail_source"], trail_bucket=config["trail_bucket"],
                            trail_prefixes=config["trail_prefixes"]))
    return rows


def connection_job(repo, cid, *, active=False):
    """Include the whole queue, including CANCELLING jobs, across worker replicas."""
    def matches(job):
        return (job.kind == JOB_KIND and job.payload.get("coverage_connection_id") == str(cid)
                and (not active or job.status in ("QUEUED", "RUNNING", "CANCELLING")))
    if getattr(repo, "engine", None) is None:
        with repo._lock:
            return max((job for job in repo.jobs.values() if matches(job)),
                       key=lambda job: job.created_at, default=None)
    from cremore.db.schema import scan_jobs
    query = select(scan_jobs.c.id).where(scan_jobs.c.kind == JOB_KIND,
        scan_jobs.c.payload["coverage_connection_id"].as_string() == str(cid))
    if active:
        query = query.where(scan_jobs.c.status.in_(("QUEUED", "RUNNING", "CANCELLING")))
    with repo.engine.connect() as conn:
        jid = conn.execute(query.order_by(scan_jobs.c.created_at.desc()).limit(1)).scalar()
    return repo.get_job(jid) if jid else None


def scheduled_refusal(repo, settings, spec):
    """Recheck at execution/checkpoint time; a queued schedule is not permission."""
    if code := feature_refusal(repo, spec):
        return code
    if spec.schedule_source == "connection":
        if not (settings.scan_schedules_allowed and spec.schedule_minutes):
            return "AWS_INVENTORY_AUTOMATION_DISABLED"
        # Periodic value reads also need the installation's AWS automatic collection to take the account
        # (owner decision 2026-10-08); other connection schedules keep their own contract.
        if spec.value_reader_role and not aws_inventory_settings.account_allowed(settings, repo, spec.account_id):
            return "VALUE_READER_AUTOMATION_DISABLED"
        return None
    if not aws_inventory_settings.account_allowed(settings, repo, spec.account_id):
        return "AWS_INVENTORY_AUTOMATION_DISABLED"
    config = aws_inventory_settings.config(settings, repo)
    if spec.provider == "aws_cloudtrail" and (not config["cloudtrail_enabled"]
            or not set(spec.regions) <= set(config["regions"])
            or spec.window_days > config["window_days"]
            or spec.cloudtrail_source != config["cloudtrail_source"]
            or spec.trail_bucket != config["trail_bucket"]
            or not set(spec.trail_prefixes) <= set(config["trail_prefixes"])):
        return "AWS_INVENTORY_CLOUDTRAIL_SCOPE_CHANGED"
    return None


def _feature_enabled(repo, account_id, purpose):
    from cremore.onboarding.store import child_feature_enabled

    account = next((row for row in repo.list_aws_accounts() if row.account_id == account_id), None)
    return account is None or child_feature_enabled(repo, "aws", account.id, purpose)


def feature_refusal(repo, spec):
    purpose = "inventory" if spec.provider in {"aws_iam", "aws_cloudtrail"} else "vault"
    return None if _feature_enabled(repo, spec.account_id, purpose) else "PROVIDER_FEATURE_PAUSED"


def enqueue_aws_inventory(repo, settings, aws_sessions, connection_id, *, actor="aws-inventory",
                          scheduled=False, now=None):
    store = CoverageStore(repo)
    cid = uuid.UUID(str(connection_id))
    candidate = store.get(cid)
    if not candidate or not candidate["enabled"]:
        raise CoverageError("CONNECTION_DISABLED_OR_MISSING")
    if candidate["spec"].get("schema_version", 1) != 1:
        raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
    spec = ConnectionSpec.model_validate(candidate["spec"])
    if not worker_collected(spec) or not spec.provider.startswith("aws_"):
        raise CoverageError("INVALID_INVENTORY_PROVIDER")
    if code := feature_refusal(repo, spec):
        raise aws_access.AccessBlocked(code)
    if aws_sessions is None:
        raise aws_access.AccessBlocked("AWS_SESSION_UNAVAILABLE")
    # Identity probing may do I/O: it must precede the database transaction.
    code, account, approval = aws_sessions.refusal(spec.account_id, aws_access.SCANNER)
    if code:
        raise aws_access.AccessBlocked(code)
    pin = aws_access.validation_key(account, aws_access.SCANNER, approval["revision"])
    now = utc(now or datetime.now(UTC))
    with store.transaction() as conn:
        bound = TaskStore(repo)._bound(conn)
        from cremore.coverage.job import require_current_access
        # Same account/approval -> connection lock order as the collecting job.
        require_current_access(bound, spec.account_id, pin, settings, scheduled_spec=spec if scheduled else None,
                               feature_spec=spec)
        row = CoverageStore(bound)._get(conn, "connections", cid, lock=True)
        if not row or not row["enabled"] or row["revision"] != candidate["revision"]:
            raise CoverageError("CONNECTION_REVISION_CONFLICT")
        existing = connection_job(bound, cid, active=True)
        if existing:
            return {"job_id": existing.id, "status": existing.status, "enqueued": False}
        if scheduled:
            interval = spec.schedule_minutes or aws_inventory_settings.config(settings, bound)["interval_minutes"]
            latest = connection_job(bound, cid)
            if now < next_collection_at(bound, "aws-inventory-schedule:" + str(cid), latest, interval, now=now):
                return {"job_id": latest.id if latest else None, "status": "NOT_DUE", "enqueued": False}
        payload = {"provider": "aws", "account_id": spec.account_id,
                   "coverage_connection_id": str(cid), "coverage_revision": row["revision"], "access_pin": pin}
        if scheduled:
            payload["aws_inventory_scheduled"] = True
        job = bound.enqueue_job(ScanJob(kind=JOB_KIND, payload=payload))
        bound.put_setting("aws-inventory-schedule:" + str(cid),
                          {"queued_at": now.isoformat(), "revision": row["revision"], "job_id": str(job.id)}, actor)
        return {"job_id": job.id, "status": job.status, "enqueued": True}


def enqueue_server_vault(repo, connection_id, *, actor="api", scheduled=False, now=None):
    """Queue one server collection of a Vault/OpenBao store; no AWS approval is involved."""
    store = CoverageStore(repo)
    cid = uuid.UUID(str(connection_id))
    now = utc(now or datetime.now(UTC))
    with store.transaction() as conn:
        bound = TaskStore(repo)._bound(conn)
        row = CoverageStore(bound)._get(conn, "connections", cid, lock=True)
        if not row or not row["enabled"]:
            raise CoverageError("CONNECTION_DISABLED_OR_MISSING")
        spec = ConnectionSpec.model_validate(row["spec"])
        if spec.provider not in ("vault", "openbao") or not spec.server_collection:
            raise CoverageError("INVALID_INVENTORY_PROVIDER")
        existing = connection_job(bound, cid, active=True)
        if existing:
            return {"job_id": existing.id, "status": existing.status, "enqueued": False}
        receipt_key = "vault-collection-schedule:" + str(cid)
        if scheduled:
            latest = connection_job(bound, cid)
            if not spec.schedule_minutes or now < next_collection_at(
                    bound, receipt_key, latest, spec.schedule_minutes, revision=row["revision"], now=now):
                return {"job_id": latest.id if latest else None, "status": "NOT_DUE", "enqueued": False}
        job = bound.enqueue_job(ScanJob(kind=JOB_KIND, payload={
            "provider": spec.provider, "coverage_connection_id": str(cid), "coverage_revision": row["revision"]}))
        bound.put_setting(receipt_key, {"queued_at": now.isoformat(), "revision": row["revision"],
                                        "job_id": str(job.id)}, actor)
        return {"job_id": job.id, "status": job.status, "enqueued": True}


def poll_server_vault_schedules(repo, settings, *, now=None):
    """Only an explicit interval on a server-collected Vault/OpenBao connection schedules it."""
    result = {"enqueued": 0, "skipped": 0}
    if not settings.scan_schedules_allowed:
        return result
    for row in CoverageStore(repo).list_connections():
        spec = row["spec"]
        if (row["enabled"] and spec.get("schema_version", 1) == 1 and spec.get("provider") in ("vault", "openbao")
                and spec.get("server_collection") and spec.get("schedule_minutes")):
            queued = enqueue_server_vault(repo, row["id"], actor="vault-collection-schedule", scheduled=True, now=now)
            result["enqueued" if queued["enqueued"] else "skipped"] += 1
    return result


def poll_aws_inventory_schedules(repo, settings, aws_sessions, *, now=None):
    result = {"enqueued": 0, "skipped": 0, "blocked": 0}
    if not settings.scan_schedules_allowed or aws_sessions is None:
        return result
    scheduled_by_account = {}
    for row in CoverageStore(repo).list_connections():
        spec = row["spec"]
        if (row["enabled"] and spec.get("schema_version", 1) == 1 and spec.get("schedule_minutes")
                and (spec.get("server_collection") or spec.get("schedule_source") == "connection")):
            scheduled_by_account.setdefault(spec.get("account_id"), []).append(row)
    for account in repo.list_aws_accounts():
        legacy = aws_inventory_settings.account_allowed(settings, repo, account.account_id)
        scheduled = scheduled_by_account.get(account.account_id, [])
        # A value-reader collection runs on its own schedule only where the legacy setting takes the account too.
        explicit = [row for row in scheduled if row["spec"].get("schedule_source") == "connection"
                    and (legacy or not row["spec"].get("value_reader_role"))]
        if not legacy and not explicit:
            continue
        try:
            code, _, _ = aws_sessions.refusal(account.account_id, aws_access.SCANNER)
            if code:
                result["blocked"] += 1
                continue
            rows = (ensure_aws_inventory_connections(repo, settings, account, "aws-inventory-schedule")
                    if legacy and _feature_enabled(repo, account.account_id, "inventory") else [])
            # A server-collected secret store is scheduled only by its own explicit interval.
            vault_enabled = _feature_enabled(repo, account.account_id, "vault")
            rows += [row for row in scheduled if legacy and vault_enabled and row["spec"].get("server_collection")]
            rows += explicit
        except Exception:  # noqa: BLE001 -- a failed account must not starve later approved accounts.
            result["blocked"] += 1
            continue
        for row in {row["id"]: row for row in rows}.values():
            try:
                queued = enqueue_aws_inventory(repo, settings, aws_sessions, row["id"],
                                               actor="aws-inventory-schedule", scheduled=True, now=now)
                result["enqueued" if queued["enqueued"] else "skipped"] += 1
            except Exception:  # noqa: BLE001 -- keep provider errors private and retry this account on the next poll.
                result["blocked"] += 1
    return result
