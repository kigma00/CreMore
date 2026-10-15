"""Durable, account-approved CloudTrail investigation on the existing worker queue."""

import copy
import datetime as dt
import hashlib
import time
import uuid

from cremore_aws_provider import aws_access, aws_identity
from cremore_aws_provider.aws_sessions import account_of_arn
from cremore_aws_provider.investigation import investigation_switches as switches
from cremore_aws_provider.investigation import usage_pages as pages
from cremore_aws_provider.investigation.usage import CredentialUsageService, empty_usage

from cremore.collectors.base import CollectorError
from cremore.coverage.job import require_current_access
from cremore.db.settings_store import locked_settings
from cremore.db.task_store import TaskStore
from cremore.domain.models import ACTIVE_JOB_STATUSES, ScanJob

JOB_KIND = "credential-usage"
PAGES_PER_TURN = 20
MAX_ELAPSED = dt.timedelta(hours=6)


def job_for(repo, cred):
    value = (cred.usage_snapshot or {}).get("refresh_job_id")
    job = repo.get_job(uuid.UUID(value)) if value else None
    return job if job and job.kind == JOB_KIND and job.payload.get("credential_id") == str(cred.id) else None


def public_job(repo, cred):
    job = job_for(repo, cred)
    if not job:
        return None
    states = TaskStore(repo).run_states(job.id)
    return {"id": str(job.id), "status": job.status,
            "error_code": states["hold_code"] or (states["failures"][0]["code"] if states["failures"] else None)}


def enqueue(repo, settings, cred, session, owner_arn, owner_user="", *, owner_evidence=None):
    with locked_settings(repo, account_id=session.account_id) as bound:
        require_current_access(bound, session.account_id, session.pin, settings)
        current = bound.get_credential(cred.id)
        job = job_for(bound, current)
        if job and job.status in ACTIVE_JOB_STATUSES:
            return job
        job = bound.enqueue_job(ScanJob(kind=JOB_KIND, payload={
            "provider": "aws", "credential_id": str(cred.id), "account_id": session.account_id,
            "access_pin": session.pin, "principal_arn": owner_arn}))
        changes = {"usage_snapshot": {**(current.usage_snapshot or empty_usage(cred.identifier)),
                                       "refresh_job_id": str(job.id)}}
        if owner_evidence:
            changes["usage_snapshot"]["owner_lookup"] = owner_evidence
        if not current.principal_arn:
            changes.update(principal_arn=owner_arn, principal_arn_source=(owner_evidence or {}).get("source", "IAM_OWNER_LOOKUP"),
                           **({"principal_name": owner_user} if owner_user else {}))
        bound.update_credential(cred.id, **changes)
        return job


def _metadata(session, cred, usage, settings, repo, check):
    from cremore_aws_provider.investigation.identity_policies import collect_identity_policies
    from cremore_aws_provider.investigation.potential_access import service_for
    from cremore_aws_provider.investigation.usage import (
        access_key_metadata,
        potential_access_view,
        require_usage_session,
    )

    check()
    extra = {"access_key": access_key_metadata(session, cred)}
    check()
    extra["identity_policies"] = collect_identity_policies(session.client("iam"), cred.principal_arn)
    if switches.effective(settings, repo, switches.POTENTIAL_ACCESS):
        check()
        # The policies just read name the resources the simulation checks beyond ``*``.
        extra["potential_access"] = potential_access_view(service_for(session).collect(
            cred.principal_arn, identity_policies=extra["identity_policies"]))
    require_usage_session(extra)
    check()
    last = usage.last_used(cred.identifier)
    extra["last_used"] = last.snapshot()
    changes = {}
    key = extra["access_key"]
    if key.get("status") in ("Active", "Inactive"):
        changes["credential_status"] = key["status"]
    if key.get("created_at"):
        changes["credential_created_at"] = dt.datetime.fromisoformat(key["created_at"])
    if last.status == "AVAILABLE" and last.at is not None:
        changes.update(last_used_at=last.at, last_used_service=last.service or None, last_used_region=last.region or None)
    return extra, changes


def run(worker, job, task, context):
    repo, settings = worker.repo, worker.settings
    if worker.aws_sessions is None:
        raise CollectorError("AWS_SESSION_UNAVAILABLE")
    cid = uuid.UUID(job.payload["credential_id"])
    account, pin = job.payload["account_id"], job.payload["access_pin"]
    session = worker.aws_sessions.open(account, aws_access.SCANNER)
    if session.pin != pin:
        raise CollectorError("AWS_ACCESS_REVISION_CHANGED")

    def check(bound=None):
        target = bound or repo
        cred = target.get_credential(cid)
        if (cred is None or account_of_arn(cred.principal_arn) != account
                or cred.principal_arn != job.payload["principal_arn"]
                or (cred.usage_snapshot or {}).get("refresh_job_id") != str(job.id)):
            raise CollectorError("USAGE_TARGET_CHANGED")
        if not switches.effective(settings, target, switches.USAGE_LOOKUP):
            raise CollectorError("USAGE_LOOKUP_OFF")
        if bound is not None:
            require_current_access(bound, account, pin, settings)
        else:
            with context():
                pass
            code, current, approved = worker.aws_sessions.refusal(account, aws_access.SCANNER)
            if code:
                if aws_identity.is_login_required(code):
                    raise aws_identity.AwsLoginRequired()
                raise CollectorError(code)
            if aws_access.validation_key(current, aws_access.SCANNER, approved["revision"]) != pin:
                raise CollectorError("AWS_ACCESS_REVISION_CHANGED")
        return cred

    state = copy.deepcopy(task.get("checkpoint") or {})
    usage = CredentialUsageService(lambda region: session.client("cloudtrail", region),
                                   session.client("ec2", settings.aws_region), session.client("iam"), region_limit=100)
    cred = check()
    if not state:
        end = dt.datetime.now(dt.UTC)
        start = end - dt.timedelta(days=90)
        regions, discovery, error = usage.regions()
        if aws_identity.is_login_required(error):
            raise aws_identity.AwsLoginRequired()
        extra, changes = _metadata(session, cred, usage, settings, repo, check)
        snapshot = {**pages.start_snapshot(cred.identifier, regions, discovery, error, start.isoformat(), end.isoformat()),
                    **session.evidence(), **extra, "refresh_job_id": str(job.id)}
        if owner_evidence := (cred.usage_snapshot or {}).get("owner_lookup"):
            snapshot["owner_lookup"] = owner_evidence
        state = {"index": 0, "cursor": None, "seen": [], "requests": 0}
        with context() as bound:
            check(bound)
            bound.update_credential(cid, usage_snapshot=snapshot, **changes)
            TaskStore(bound).checkpoint(task["id"], task["token"], state)
    snapshot = copy.deepcopy(repo.get_credential(cid).usage_snapshot)
    clients = {}
    for _ in range(PAGES_PER_TURN):
        if state["index"] >= len(snapshot["coverage"]):
            break
        expired = dt.datetime.now(dt.UTC) - dt.datetime.fromisoformat(snapshot["window_end"]) > MAX_ELAPSED
        if state["requests"] >= pages.MAX_REQUESTS or expired:
            for row in snapshot["coverage"][state["index"]:]:
                row.update(status="CAPPED", error_code="TIME_LIMIT_REACHED" if expired else "REQUEST_LIMIT_REACHED")
            state["index"] = len(snapshot["coverage"])
            break
        cred = check()
        index = state["index"]
        row = snapshot["coverage"][index]
        # Charge before I/O, so a crash/retry cannot reset the request budget.
        state["requests"] += 1
        with context() as bound:
            check(bound)
            TaskStore(bound).checkpoint(task["id"], task["token"], state)
        try:
            if row["region"] not in clients:
                clients[row["region"]] = session.client("cloudtrail", row["region"])
            events, following = pages.read_page(clients[row["region"]], cred.identifier,
                row["region"], snapshot["window_start"], snapshot["window_end"], state["cursor"], state["seen"])
        except Exception as exc:
            if aws_identity.is_login_required(exc):
                raise aws_identity.AwsLoginRequired() from exc
            row.update(status="FAILED", error_code=aws_identity.collection_error_code(exc))
            following = None
        else:
            pages.add_page(snapshot, index, events, following)
        snapshot["requests_used"] = state["requests"]
        if following:
            state["cursor"] = following
            state["seen"].append(hashlib.sha256(following.encode()).hexdigest())
        else:
            state.update(index=index + 1, cursor=None, seen=[])
        with context() as bound:
            check(bound)
            bound.update_credential(cid, usage_snapshot=pages.finish_view(snapshot))
            TaskStore(bound).checkpoint(task["id"], task["token"], state)
        # Account tasks are serialized by the queue; spacing survives chunks via defer.
        time.sleep(0.55)
    if state["index"] >= len(snapshot["coverage"]):
        with context() as bound:
            check(bound)
            bound.update_credential(cid, usage_snapshot=pages.finish_view(snapshot))
            TaskStore(bound).finish(task["id"], task["token"], {
                "objects": snapshot["summary"]["events"], "requests": state["requests"],
                "root_coverage_complete": snapshot["collection_status"] == "COMPLETE"})
    else:
        worker.runtime.tasks.defer(task["id"], task["token"], "USAGE_PAGINATION_PENDING", delay_seconds=1)
